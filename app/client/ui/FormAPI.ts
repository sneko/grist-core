import { BaseAPI, IOptions } from "app/common/BaseAPI";
import { CellValue, ColValues } from "app/common/DocActions";
import {
  decryptFormSpec, encryptFormAnswer, encryptFormFile, FormAnswerFile, FormSpec,
} from "app/common/encryption/EncryptedForms";
import { base64ToBytes, bytesToBase64 } from "app/common/encryption/EncryptionCrypto";
import { addCurrentOrgToPath } from "app/common/urlUtils";

/**
 * Form and associated field metadata from a Grist view section.
 *
 * Includes the layout of the form, metadata such as the form title, and
 * a map of data for each field in the form. All of this is used to build a
 * submittable version of the form (see `FormRenderer.ts`, which handles the
 * actual building of forms).
 */
export interface Form {
  formFieldsById: Record<number, FormField>;
  formLayoutSpec: string;
  formTitle: string;
  formTableId: string;
}

/**
 * Metadata for a field in a form.
 *
 * Form fields are directly related to Grist fields; the former is based on data
 * from the latter, with additional metadata specific to forms, like whether a
 * form field is required. All of this is used to build a field in a submittable
 * version of the form (see `FormRenderer.ts`, which handles the actual building
 * of forms).
 */
export interface FormField {
  /** The field label. Defaults to the Grist column label or id. */
  question: string;
  /** The field description. */
  description: string;
  /** The Grist column id of the field. */
  colId: string;
  /** The Grist column type of the field (e.g. "Text"). */
  type: string;
  /** Additional field options. */
  options: FormFieldOptions;
  /** Populated with data from a referenced table. Only set if `type` is a Reference type. */
  refValues: [number, CellValue][] | null;
}

export interface FormFieldOptions {
  /** Choices for a Choice or Choice List field. */
  choices?: string[];
  /** Text or Any field format. Defaults to `"singleline"`. */
  formTextFormat?: FormTextFormat;
  /** Number of lines/rows for the `"multiline"` option of `formTextFormat`. Defaults to `3`. */
  formTextLineCount?: number;
  /** Maximum length for the text response. */
  formTextMaximumLength?: number;
  /** Numeric or Int field format. Defaults to `"text"`. */
  formNumberFormat?: FormNumberFormat;
  /** Toggle field format. Defaults to `"switch"`. */
  formToggleFormat?: FormToggleFormat;
  /** Choice or Reference field format. Defaults to `"select"`. */
  formSelectFormat?: FormSelectFormat;
  /**
   * Field options alignment.
   *
   * Only applicable to Choice List and Reference List fields, and Choice and Reference fields
   * when `formSelectFormat` is `"radio"`.
   *
   * Defaults to `"vertical"`.
   */
  formOptionsAlignment?: FormOptionsAlignment;
  /**
   * Field options sort order.
   *
   * Only applicable to Choice, Choice List, Reference, and Reference List fields.
   *
   * Defaults to `"default"`.
   */
  formOptionsSortOrder?: FormOptionsSortOrder;
  /**
   * Maximum number of options to display for Choice List and Reference List fields.
   *
   * Defaults to `30`.
   */
  formOptionsLimit?: number;
  /** True if the field is required. Defaults to `false`. */
  formRequired?: boolean;
  /** True if the field is marked as hidden, to hide from users. Defaults to false. */
  formIsHidden?: boolean;
  /** If set, this field will allow values to be set via URL. */
  formAcceptFromUrl?: boolean;
}

export type FormTextFormat = "singleline" | "multiline";

export type FormNumberFormat = "text" | "spinner";

export type FormToggleFormat = "switch" | "checkbox";

export type FormSelectFormat = "select" | "radio";

export type FormOptionsAlignment = "vertical" | "horizontal";

export type FormOptionsSortOrder = "default" | "ascending" | "descending";

export const FORM_OPTIONS_DEFAULT_LIMIT = 30;

export function getFormOptionsLimit(options: FormFieldOptions): number {
  return options.formOptionsLimit || FORM_OPTIONS_DEFAULT_LIMIT;
}

export interface FormAPI {
  getForm(options: GetFormOptions): Promise<Form>;
  createRecord(options: CreateRecordOptions): Promise<number>;
  createAttachments(options: CreateAttachmentOptions): Promise<number[]>;
}

interface FormTargetWithDocId {
  docId: string;
}

interface FormTargetWithShareKey {
  shareKey: string;
}

type FormTarget = FormTargetWithDocId | FormTargetWithShareKey;

interface GetFormCommonOptions {
  vsId: number;
}

type GetFormOptions = GetFormCommonOptions & FormTarget;

interface CreateRecordCommonOptions {
  tableId: string;
  colValues: ColValues;
}

type CreateRecordOptions = CreateRecordCommonOptions & FormTarget;

interface CreateAttachmentCommonOptions {
  upload: File[];
}

type CreateAttachmentOptions = CreateAttachmentCommonOptions & FormTarget;

export class FormAPIImpl extends BaseAPI implements FormAPI {
  constructor(private _homeUrl: string, options: IOptions = {}) {
    super(options);
  }

  public async getForm(options: GetFormOptions): Promise<Form> {
    const { vsId } = options;
    return this.requestJson(this._docOrShareUrl(`/forms/${vsId}`, options), {
      method: "GET",
    });
  }

  public async createRecord(options: CreateRecordOptions): Promise<number> {
    const { tableId, colValues } = options;
    const response = await this.requestJson(
      this._docOrShareUrl(`/tables/${tableId}/records`, options),
      {
        method: "POST",
        body: JSON.stringify({ records: [{ fields: colValues }] }),
      },
    );
    // If we don't retrieve the record ID, we can reasonably assume the creation has failed
    // and throw an error.
    if (!(response?.records?.[0]?.id)) {
      throw new Error("Record creation failed");
    }
    return response.records[0].id;
  }

  public async createAttachments(options: CreateAttachmentOptions): Promise<number[]> {
    const upload = options.upload.filter(f => f.size > 0);
    if (upload.length === 0) {
      return [];
    }

    const formData = new FormData();
    for (const file of upload) {
      formData.append("upload", file);
    }

    return this.requestJson(this._docOrShareUrl("/attachments", options), {
      method: "POST",
      headers: { ...this.defaultHeadersWithoutContentType() },
      body: formData,
    });
  }

  private get _baseUrl(): string {
    return addCurrentOrgToPath(this._homeUrl);
  }

  private _docOrShareUrl(path: string, target: FormTarget): string {
    const base =
      "docId" in target ?
        `${this._baseUrl}/api/docs/${target.docId}` :
        `${this._baseUrl}/api/s/${target.shareKey}`;
    const url = new URL(`${base}${path}`);
    if ("shareKey" in target) {
      url.searchParams.set("utm_source", "grist-forms");
    }
    return url.href;
  }
}

/**
 * Forms of end-to-end encrypted documents (see app/common/encryption/EncryptedForms.ts): the form
 * is encrypted with a key that's in the link (after "#", which browsers never send to servers),
 * and answers are encrypted, in the browser, for the document's members only.
 */
export class EncryptedFormAPI extends BaseAPI implements FormAPI {
  private _spec?: FormSpec;
  // Files attached in the answer being made (see createAttachments()).
  private _files: FormAnswerFile[] = [];

  constructor(private _homeUrl: string, private _docId: string, private _formId: string, private _linkKey: string,
    options: IOptions = {}) {
    super(options);
  }

  public async getForm(): Promise<Form> {
    const { spec } = await this.requestJson(this._url(), { method: "GET" });
    this._spec = await decryptFormSpec(this._linkKey, base64ToBytes(spec));
    if (this._spec.formId !== this._formId) { throw new Error("Invalid form"); }
    return this._spec.form;
  }

  public async createRecord(options: CreateRecordOptions): Promise<number> {
    if (!this._spec) { throw new Error("Form not loaded"); }
    const payload = await encryptFormAnswer(this._spec.publicKey, {
      v: 1, tableId: options.tableId, colValues: options.colValues,
      ...(this._files.length > 0 ? { files: this._files } : {}),
    });
    await this.requestJson(this._url(), {
      method: "POST",
      body: JSON.stringify({ payload: bytesToBase64(payload), fileIds: this._files.map(f => f.fileId) }),
    });
    this._files = [];
    // (The record is created later, by a member of the document.)
    return 0;
  }

  /**
   * Encrypts files attached in the answer, each with a key of its own, and sends them. Returns the
   * ids the answer's cells refer to them by (see FormAnswer.files).
   */
  public async createAttachments(options: CreateAttachmentOptions): Promise<number[]> {
    const ids: number[] = [];
    for (const file of options.upload.filter(f => f.size > 0)) {
      const { key, payload } = await encryptFormFile(new Uint8Array(await file.arrayBuffer()));
      const { fileId } = await this.requestJson(`${this._url()}/files`, {
        method: "POST",
        headers: { ...this.defaultHeadersWithoutContentType(), "Content-Type": "application/octet-stream" },
        body: payload as BodyInit,
      });
      this._files.push({ fileId, key, name: file.name, size: file.size });
      ids.push(-this._files.length);
    }
    return ids;
  }

  private _url() {
    return `${addCurrentOrgToPath(this._homeUrl)}/api/docs/${this._docId}/encrypted-forms/${this._formId}`;
  }
}
