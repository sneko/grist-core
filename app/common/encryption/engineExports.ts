/**
 * Functions the data engine calls back into (via call_external in Python), when it runs in the
 * browser for an end-to-end encrypted document. On the server, ActiveDoc provides the same ones.
 */
import { EngineExports } from "app/common/encryption/PyodideEngine";
import { convertFromColumn } from "app/common/ValueConverter";
import { guessColInfo } from "app/common/ValueGuesser";

export const engineExports: EngineExports = {
  guessColInfo,
  convertFromColumn,
  request: () => {
    // REQUEST() makes HTTP calls from the server, which can't see encrypted data.
    throw new Error("REQUEST is not available in end-to-end encrypted documents");
  },
};
