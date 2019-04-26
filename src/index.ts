/**
 * https://dl2.dev - DL2 IT Services
 * Owlsome solutions. Owltstanding results.
 */

import { sign, verify } from "jsonwebtoken";

// prettier-ignore
export const APP_JWT_SECRET = process.env.JWT_SECRET || `DL2+DEV--JWT-SECRET`;

export interface IdentityAttributes {
  email: string;
  id: string;
  isAdmin: boolean;
  isStaff: boolean;
  name: string;
  surname: string;
  userAgent: string;
  username: string;
  verified: boolean;
}

export class Identity {
  public get email(): string {
    return this.$attributes!.email;
  }

  public get id(): string {
    return this.$attributes!.id;
  }

  public get isAdmin(): boolean {
    return !!this.$attributes!.isAdmin;
  }

  public get isStaff(): boolean {
    return !!this.$attributes!.isStaff || this.isAdmin;
  }

  public get displayName(): string[] {
    return [this.$attributes!.name, this.$attributes!.surname];
  }

  public get userAgent(): string {
    return this.$attributes!.userAgent;
  }

  public get username(): string {
    return this.$attributes!.username;
  }

  public get verified(): boolean {
    return !!this.$attributes!.verified;
  }

  /**
   * Create e new `Identity` from the given `header` or `Request`.
   */
  public static fromHeader(input: string | any): Identity {
    if (typeof input !== "string") {
      const headers = { authorization: undefined, ...input.headers };
      const bearer = `${headers.authorization}`.split(" ");

      // empty or invalid headers sent
      if (bearer.length !== 2 && bearer[0].toLowerCase() !== "bearer") {
        throw new Error("empty or invalid headers sent");
      }

      input = bearer[1];
    }

    return this.fromToken(input as string);
  }

  /**
   * Create a new `Identity` from the given bearer token.
   */
  public static fromToken(token: string): Identity {
    const {
      email,
      id,
      isAdmin,
      isStaff,
      name,
      surname,
      userAgent,
      username,
      verified,
    } = verify(token, APP_JWT_SECRET) as IdentityAttributes;

    return new Identity({
      email,
      id,
      isAdmin,
      isStaff,
      name,
      surname,
      userAgent,
      username,
      verified,
    });
  }

  constructor(protected readonly $attributes?: IdentityAttributes) {
    //
  }

  /**
   * Sign (or refresh) the current `Identity` into a `jsonwebtoken`
   * returning both identity attributes and the signed token.
   */
  public sign(): Partial<IdentityAttributes & { token: string }> {
    return {
      ...this.$attributes,
      token: sign(this.$attributes!, APP_JWT_SECRET, { expiresIn: "1d" }),
    };
  }

  /**
   * Return the identity attributes in JSON format.
   */
  public toJson(): IdentityAttributes {
    return this.$attributes!;
  }
}
