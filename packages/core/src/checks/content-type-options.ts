import { type Check, result } from "./context.js";

export const contentTypeOptions: Check = ({ headers }) => {
  const base = {
    id: "content-type-options" as const,
    title: "X-Content-Type-Options",
    headers: ["x-content-type-options"],
    defends: "MIME sniffing that turns uploads into scripts",
  };
  const value = headers.first("x-content-type-options");
  if (!value) {
    return result({ ...base, summary: "Missing" }, [
      { id: "xcto.missing", severity: "medium", message: "Browsers may guess a file's type, so an uploaded text file can end up executed as script.", modifier: -5 },
    ]);
  }
  if (value.trim().toLowerCase() !== "nosniff") {
    return result({ ...base, summary: "Invalid value", value }, [
      { id: "xcto.invalid", severity: "medium", message: `The only valid value is "nosniff"; "${value}" is ignored.`, modifier: -5, evidence: value },
    ]);
  }
  return result({ ...base, summary: "nosniff", value }, []);
};
