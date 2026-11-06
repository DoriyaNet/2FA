import { createApiHandler } from "../server/api.js";

export const config = {
  api: {
    bodyParser: false,
  },
};

export default createApiHandler();
