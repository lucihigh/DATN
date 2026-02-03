import createClient from "openapi-fetch";
import type { paths } from "./types";

const API_BASE =
  (typeof process !== "undefined" && process.env.API_BASE_URL) || "http://localhost:4000";

export const api = createClient<paths>({ baseUrl: API_BASE });
