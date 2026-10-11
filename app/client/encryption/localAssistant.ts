/**
 * The formula assistant for encrypted documents. The server can't read them, so it can't build
 * the request to the AI service, as it does for regular documents: the browser does, and calls the
 * AI service configured for encrypted documents directly (see EncryptionAssistantConfig).
 *
 * What's sent (the document's structure: tables, columns, their types and formulas, and the
 * user's questions) leaves the encrypted document: the user must agree to it, for each session,
 * knowing who runs the service and whether it's sovereign. With "user-key" authentication, each
 * user also gives an API key of their own, kept in their browser only.
 */
import { makeT } from "app/client/lib/localization";
import { getSessionStorage, getStorage } from "app/client/lib/storage";
import { textInput } from "app/client/ui/inputs";
import { bigBasicButton, bigPrimaryButton } from "app/client/ui2018/buttons";
import { testId, theme } from "app/client/ui2018/cssVars";
import { cssModalBody, cssModalButtons, cssModalTitle, modal } from "app/client/ui2018/modals";
import { AssistanceMessage, AssistanceRequestV1, AssistanceResponseV1 } from "app/common/Assistance";
import { EncryptionAssistantConfig } from "app/common/gristUrls";

import { dom, Observable, styled } from "grainjs";

const t = makeT("localAssistant");

const CONSENT_KEY = "grist-encryption-assistant-consent";
const API_KEY = "grist-encryption-assistant-key";

/** What the assistant needs from the document (served by its local data engine). */
export interface LocalAssistantDoc {
  getFormulaPrompt(tableId: string, colId: string,
    options: { includeAllTables: boolean, includeLookups: boolean }): Promise<string>;
  convertFormulaCompletion(completion: string): Promise<string>;
}

export class AssistantNotAllowedError extends Error {}

/** Answers a request for formula assistance, calling the AI service from the browser. */
export async function getLocalAssistance(config: EncryptionAssistantConfig, doc: LocalAssistantDoc,
  request: AssistanceRequestV1): Promise<AssistanceResponseV1> {
  await ensureConsent(config);
  const apiKey = config.auth === "user-key" ? await ensureApiKey(config) : null;
  const { tableId, colId } = request.context;
  const messages: AssistanceMessage[] = [...(request.state?.messages || [])];
  if (messages.length === 0) {
    messages.push(await makeSystemMessage(doc, tableId, colId, { includeAllTables: true, includeLookups: true }));
  }
  messages.push({ role: "user", content: request.text || "" });
  let completion: string;
  try {
    completion = await fetchCompletion(config, apiKey, messages);
  } catch (e) {
    if (!(e instanceof ContextTooLongError)) { throw e; }
    // As the server does, try again with a shorter description of the document.
    messages[0] = await makeSystemMessage(doc, tableId, colId, { includeAllTables: false, includeLookups: false });
    completion = await fetchCompletion(config, apiKey, messages);
  }
  messages.push({ role: "assistant", content: completion });
  const suggestedFormula = await doc.convertFormulaCompletion(completion) || undefined;
  return {
    suggestedActions: suggestedFormula ? [["ModifyColumn", tableId, colId, { formula: suggestedFormula }]] : [],
    suggestedFormula,
    reply: suggestedFormula ?
      completion.replace(/```\w*\n(.*)```/s, "```python\n" + suggestedFormula + "\n```") :
      completion,
    state: { messages },
  };
}

/** Forgets the user's API key and consent (in this browser). */
export function forgetAssistantSettings() {
  getStorage().removeItem(API_KEY);
  getSessionStorage().removeItem(CONSENT_KEY);
}

class ContextTooLongError extends Error {}

async function makeSystemMessage(doc: LocalAssistantDoc, tableId: string, colId: string,
  options: { includeAllTables: boolean, includeLookups: boolean }): Promise<AssistanceMessage> {
  // The same instructions as the server gives (see OpenAIAssistantV1).
  return {
    role: "system",
    content:
      "You are a helpful assistant for a user of software called Grist. " +
      "Below are one or more fake Python classes representing the structure of the user's data. " +
      "The function at the end needs completing. " +
      "The user will probably give a description of what they want the function (a 'formula') to return. " +
      "If so, your response should include the function BODY as Python code in a markdown block. " +
      "Your response will be automatically concatenated to the code below, so you mustn't repeat any of it. " +
      "You cannot change the function signature or define additional functions or classes. " +
      "It should be a pure function that performs some computation and returns a result. " +
      "It CANNOT perform any side effects such as adding/removing/modifying rows/columns/cells/tables/etc. " +
      "It CANNOT interact with files/databases/networks/etc. " +
      "It CANNOT display images/charts/graphs/maps/etc. " +
      "If the user asks for these things, tell them that you cannot help. " +
      "\n\n```python\n" + await doc.getFormulaPrompt(tableId, colId, options) + "\n```",
  };
}

async function fetchCompletion(config: EncryptionAssistantConfig, apiKey: string | null,
  messages: AssistanceMessage[]): Promise<string> {
  const response = await fetch(config.endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    },
    body: JSON.stringify({ messages, temperature: 0, ...(config.model ? { model: config.model } : {}) }),
  });
  const text = await response.text();
  let result: any;
  try {
    result = JSON.parse(text);
  } catch (e) {
    throw new Error(t("The AI service returned an error ({{status}})", { status: response.status }));
  }
  if (result.error?.code === "context_length_exceeded" || result.choices?.[0]?.finish_reason === "length") {
    throw new ContextTooLongError();
  }
  if (response.status === 401 || response.status === 403) {
    if (config.auth === "user-key") { getStorage().removeItem(API_KEY); }
    throw new Error(t("The AI service refused the request: check your API key"));
  }
  if (!response.ok) {
    throw new Error(t("The AI service returned an error ({{status}}): {{message}}",
      { status: response.status, message: result.error?.message || "" }));
  }
  const content = result.choices?.[0]?.message?.content;
  if (typeof content !== "string") { throw new Error(t("The AI service returned an invalid answer")); }
  return content;
}

/** Asks the user, once per session, to agree to sending the document's structure to the AI service. */
function ensureConsent(config: EncryptionAssistantConfig): Promise<void> {
  if (getSessionStorage().getItem(CONSENT_KEY) === config.endpoint) { return Promise.resolve(); }
  return new Promise((resolve, reject) => {
    modal(ctl => [
      cssModalTitle(t("Send this document's structure to an AI service?")),
      cssModalBody(
        dom("p", t("This document is end-to-end encrypted. To help you with formulas, the assistant sends, " +
          "from your browser:")),
        dom("ul",
          dom("li", t("the structure of the document: names and types of its tables and columns (including " +
            "the choices of choice columns), and their formulas;")),
          dom("li", t("what you ask the assistant.")),
        ),
        dom("p", t("It doesn't send the values in cells. The service is run by {{provider}}.",
          { provider: config.provider }), " ",
        config.sovereign ?
          cssSovereign(t("It's a sovereign service."), testId("assistant-sovereign")) :
          cssNotSovereign(t("It's NOT a sovereign service: your data may be subject to foreign laws."),
            testId("assistant-not-sovereign"))),
        dom("p", t("You'll be asked again in your next session.")),
      ),
      cssModalButtons(
        bigPrimaryButton(t("I agree"), dom.on("click", () => {
          getSessionStorage().setItem(CONSENT_KEY, config.endpoint);
          ctl.close();
          resolve();
        }), testId("assistant-consent")),
        bigBasicButton(t("Cancel"), dom.on("click", () => {
          ctl.close();
          reject(new AssistantNotAllowedError(t("The AI assistant needs your agreement to be used")));
        })),
      ),
    ], { noClickAway: true });
  });
}

/** The user's API key for the AI service, asking for it if it's not known (in this browser) yet. */
function ensureApiKey(config: EncryptionAssistantConfig): Promise<string> {
  const known = getStorage().getItem(API_KEY);
  if (known) { return Promise.resolve(known); }
  return new Promise((resolve, reject) => {
    modal((ctl, owner) => {
      const key = Observable.create(owner, "");
      return [
        cssModalTitle(t("API key for {{provider}}", { provider: config.provider })),
        cssModalBody(
          dom("p", t("The AI assistant uses your own API key for this service. It's kept in this browser only " +
            "(Grist's server never sees it).")),
          textInput(key, { type: "password", placeholder: t("API key") }, testId("assistant-api-key")),
        ),
        cssModalButtons(
          bigPrimaryButton(t("Save"), dom.boolAttr("disabled", use => !use(key).trim()), dom.on("click", () => {
            getStorage().setItem(API_KEY, key.get().trim());
            ctl.close();
            resolve(key.get().trim());
          }), testId("assistant-api-key-save")),
          bigBasicButton(t("Cancel"), dom.on("click", () => {
            ctl.close();
            reject(new AssistantNotAllowedError(t("The AI assistant needs an API key")));
          })),
        ),
      ];
    }, { noClickAway: true });
  });
}

const cssSovereign = styled("span", `
  color: ${theme.controlPrimaryBg};
  font-weight: bold;
`);

const cssNotSovereign = styled("span", `
  color: ${theme.errorText};
  font-weight: bold;
`);
