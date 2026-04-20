export class SpizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpizeError";
  }
}

export class SpizeHttpError extends SpizeError {
  constructor(
    public readonly statusCode: number,
    public readonly code: string | null,
    message: string,
  ) {
    super(`[${statusCode}] ${code ?? "error"}: ${message}`);
    this.name = "SpizeHttpError";
  }
}

export class IdentityError extends SpizeError {
  constructor(message: string) {
    super(message);
    this.name = "IdentityError";
  }
}
