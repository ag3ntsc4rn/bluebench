import { describe, expect, it } from "vitest";
import { domainFromInput } from "./domain-input";

describe("domainFromInput", () => {
  it.each([
    ["example.com", "example.com"],
    ["  Example.COM ", "example.com"],
    ["https://www.example.com/login?x=1", "www.example.com"],
    ["hxxps://evil[.]example/path", "evil.example"],
    ["someone@mail.example.org", "mail.example.org"],
    ["example[.]com", "example.com"],
  ])("%j → %s", (input, expected) => {
    expect(domainFromInput(input)).toBe(expected);
  });

  it.each(["", "hello", "10.0.0.1", "http://192.0.2.1/", "d41d8cd98f00b204e9800998ecf8427e"])("rejects %j", (input) => {
    expect(domainFromInput(input)).toBeNull();
  });
});
