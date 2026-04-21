import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { Identity } from "@aexproto/sdk";

export class IdentityStore {
  constructor(private readonly path: string) {}

  async load(): Promise<Identity | null> {
    try {
      const text = await readFile(this.path, "utf8");
      return await Identity.fromJSON(JSON.parse(text));
    } catch (err) {
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code === "ENOENT") return null;
      throw err;
    }
  }

  async save(identity: Identity): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const payload = JSON.stringify(identity.toJSON(), null, 2);
    await writeFile(this.path, payload, { encoding: "utf8", mode: 0o600 });
  }

  get filePath(): string {
    return this.path;
  }
}
