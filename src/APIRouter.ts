import { Router } from "express";
import { z, ZodAny, ZodType } from "zod";
import type {
  Router as RouterType,
  Request as ExpressRequest,
  Response as ExpressResponse,
  NextFunction as ExpressNextFunction,
  RequestHandler as ExpressRequestHandler,
} from "express";
import type { IncomingHttpHeaders } from "http";
import jwt from "jsonwebtoken";
import multer from "multer";
import type { ParsedQs } from "qs";

type HTTPMethod =
  | "get"
  | "post"
  | "put"
  | "delete"
  | "patch"
  | "options"
  | "head";

type BodyType = Record<string, unknown> | undefined;
type QueryType = ParsedQs;
type ParamType = Record<string, string>;
type ResponseType = any;

export type FileUploadConfig =
  | { type: "none" }
  | { type: "single"; fieldName: string }
  | { type: "array"; fieldName: string; maxCount?: number }
  | { type: "fields"; fields: Record<string, number> };

export interface Request<
  Q extends QueryType = QueryType,
  B = Record<string, unknown> | undefined,
  P extends Record<string, string> = Record<string, string>,
  U extends FileUploadConfig = { type: "none" }
> extends ExpressRequest {
  query: Q;
  body: B;
  params: P;
  file: U extends { type: "single" } ? Express.Multer.File : undefined;
  files: U extends { type: "array" }
    ? Express.Multer.File[]
    : U extends { type: "fields" }
    ? Record<string, Express.Multer.File[]>
    : undefined;
}

export type Response<ResponseType = any> = ExpressResponse<ResponseType>;
export type NextFunction = ExpressNextFunction;

/**
 * A function that extracts user data from a request.
 * @param req The {@link Request} object
 * @returns User data
 *
 * @throws Throws {@link HTTPError} if the user is not authenticated
 */
export type AuthHandler<AuthedUserData> = (
  req: Request<any, any, any, any>
) => AuthedUserData | Promise<AuthedUserData>;

type RouteHandlerBodySchema = ZodType<BodyType>;
type RouteHandlerQuerySchema = ZodType<QueryType>;
type RouteHandlerParamSchema = ZodType<ParamType>;
type RouteHandlerResponseSchema = ZodType<ResponseType>;

export type RouteHandler<
  BodySchema extends RouteHandlerBodySchema,
  QuerySchema extends RouteHandlerQuerySchema,
  ParamSchema extends RouteHandlerParamSchema,
  ResponseSchema extends RouteHandlerBodySchema,
  Instances,
  AuthedUserData,
  FileUpload extends FileUploadConfig = { type: "none" }
> = {
  bodySchema: BodySchema;
  querySchema: QuerySchema;
  paramsSchema: ParamSchema;
  responseSchema: ResponseSchema;
  upload?: FileUpload;
} & (
  | {
      /**
       * Does this route require authentification ?
       */
      authed: true;
      /**
       *
       * @param req The request object containing the infos and data about the request
       * @param res The response object. This object is not meant to send a response (yo ucan do that by returning an object matching the responseSchema), but to set cookies or any metadata like headers. If for some reason you really need to send the response yourself (by using the response object), the handler return value will be ignored
       * @param instances The instances object passed to the router
       * @param userTokenData The data returned by the AuthHandler (the data contained in the token if you use the default jwt handler)
       * @returns The request response
       */
      handler: (
        req: Request<
          z.output<QuerySchema>,
          z.output<BodySchema>,
          z.output<ParamSchema>,
          FileUpload
        >,
        res: Response<z.output<ResponseSchema>>,
        instances: Instances,
        userTokenData: AuthedUserData
      ) => z.output<ResponseSchema> | Promise<z.output<ResponseSchema>>;
    }
  | {
      /**
       * Does this route require authentification ?
       */
      authed: false;
      /**
       *
       * @param req The request object containing the infos and data about the request
       * @param res The response object. This object is not meant to send a response (you can do that by returning an object matching the responseSchema), but to set cookies or any metadata like headers. If for some reason you really need to send the response yourself (by using the response object), the handler return value will be ignored
       * @param instances The instances object passed to the router
       * @returns The request response
       */
      handler: (
        req: Request<
          z.output<QuerySchema>,
          z.output<BodySchema>,
          z.output<ParamSchema>,
          FileUpload
        >,
        res: Response<z.output<ResponseSchema>>,
        instances: Instances
      ) => z.output<ResponseSchema> | Promise<z.output<ResponseSchema>>;
    }
);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function errorMiddleware(
  err: Error,
  req: ExpressRequest,
  res: Response<any>,
  next: NextFunction
) {
  if (err instanceof HTTPError) {
    err.sendError(res);
  } else if (err instanceof z.ZodError) {
    res.status(400).json(err.issues);
  } else {
    console.error("An error was caught by the router : ");
    console.error(err.stack);
    res.status(500).send(err.message);
  }
}

export class APIRouter<InstanceType, AuthedUserData> {
  private router: RouterType;
  private instances: InstanceType;
  private authHandler?: AuthHandler<AuthedUserData>;

  constructor(
    instances: InstanceType,
    authHandler?: AuthHandler<AuthedUserData>
  ) {
    this.router = Router();
    this.instances = instances;
    this.authHandler = authHandler;
  }

  createRouteHandler<
    BodySchema extends RouteHandlerBodySchema,
    QuerySchema extends RouteHandlerQuerySchema,
    ParamSchema extends RouteHandlerParamSchema,
    ResponseSchema extends RouteHandlerResponseSchema,
    FileUpload extends FileUploadConfig = { type: "none" }
  >(
    routeHandler: RouteHandler<
      BodySchema,
      QuerySchema,
      ParamSchema,
      ResponseSchema,
      InstanceType,
      AuthedUserData,
      FileUpload
    >
  ) {
    return routeHandler;
  }

  registerRoute<
    BodySchema extends RouteHandlerBodySchema,
    QuerySchema extends RouteHandlerQuerySchema,
    ParamSchema extends RouteHandlerParamSchema,
    ResponseSchema extends RouteHandlerResponseSchema,
    FileUpload extends FileUploadConfig = { type: "none" }
  >(
    method: HTTPMethod,
    path: string,
    routeHandler: RouteHandler<
      BodySchema,
      QuerySchema,
      ParamSchema,
      ResponseSchema,
      InstanceType,
      AuthedUserData,
      FileUpload
    >
  ) {
    const handlers: ((
      req: Request<
        z.output<QuerySchema>,
        z.output<BodySchema>,
        z.output<ParamSchema>,
        FileUpload
      >,
      res: Response<z.output<ResponseSchema>>,
      next: NextFunction
    ) => void)[] = [];

    // Auth middleware
    if (routeHandler.authed) {
      if (this.authHandler === undefined) {
        throw new Error(
          `Route handler for ${path} requires authentication, but no auth handler was provided`
        );
      }

      handlers.push(async (req, res, next) => {
        try {
          const authResult = this.authHandler!(req);
          res.locals.userTokenData =
            //   (req as any).userTokenData =
            authResult instanceof Promise ? await authResult : authResult;
          next();
        } catch (err) {
          next(err);
        }
      });
    }

    // File upload
    if (routeHandler.upload) {
      if (multer === undefined)
        throw new Error(
          'Could not find the multer middleware. To use file upload, you need to add the "multer" package'
        );
      const upload = multer({ storage: multer.memoryStorage() });
      const config = routeHandler.upload;

      if (config.type === "single")
        handlers.push(upload.single(config.fieldName));
      else if (config.type === "array")
        handlers.push(upload.array(config.fieldName, config.maxCount));
      else if (config.type === "fields") {
        const fields = Object.entries(config.fields).map(([name, len]) => ({
          name,
          maxCount: len,
        }));
        handlers.push(upload.fields(fields));
      }
    }

    // Input validation
    handlers.push((req, res, next) => {
      Object.defineProperty(req, "query", {
        value: routeHandler.querySchema.parse(req.query),
      });
      Object.defineProperty(req, "body", {
        value: routeHandler.bodySchema.parse(req.body),
      });
      Object.defineProperty(req, "params", {
        value: routeHandler.paramsSchema.parse(req.params),
      });
      next();
    });

    // Route handler
    handlers.push(async (req, res, next) => {
      try {
        let handlerResult;

        if (routeHandler.authed) {
          handlerResult = routeHandler.handler(
            req,
            res,
            this.instances,
            res.locals.userTokenData as AuthedUserData
          );
        } else {
          handlerResult = routeHandler.handler(req, res, this.instances);
        }

        const result =
          handlerResult instanceof Promise
            ? await handlerResult
            : handlerResult;

        const parsedResult = routeHandler.responseSchema.parse(result);
        if (!res.writableEnded) {
          res.status(200).json(parsedResult);
        }
      } catch (err) {
        next(err);
      }
    });

    this.router[method](
      path,
      ...(handlers as ExpressRequestHandler<
        z.output<ParamSchema>,
        z.output<ResponseSchema>,
        z.output<BodySchema>,
        z.output<QuerySchema>
      >[]),
      errorMiddleware
    );
    // z.output<QuerySchema>,
    // z.output<BodySchema>,
    // z.output<ParamSchema>,
  }

  getRouter() {
    return this.router;
  }
}
export class HTTPError extends Error {
  status: number;

  constructor(status: number, message: string = "") {
    super(message);
    this.status = status;
  }

  sendError(res: Response) {
    res.status(this.status).send(this.message);
  }
}

export type JWTAuthHandlerOptions = {
  /**
   * The secret used to verify the json web token.
   */
  auth_secret: string;
} & (
  | {
      /**
       * The source of the json web token :
       * "header" will try to parse the token in a Bearer Auth format
       * "cookie" will try to parse the token from a cookie
       */
      tokenSource: "header";
      /**
       * The header in which the token is stored. @default authorization
       */
      headerName?: keyof IncomingHttpHeaders;
    }
  | {
      /**
       * The source of the json web token :
       * "header" will try to parse the token in a Bearer Auth format
       * "cookie" will try to parse the token from a cookie
       */
      tokenSource: "cookie";

      /**
       * The cookie in which the token is stored. @default auth_token
       */
      cookieName?: string;
    }
);

/**
 * Create a default Auth Handler using the jsonwebtoken library
 * @param options the options ({@link JWTAuthHandlerOptions}) object
 * @returns the created {@link AuthHandler}
 */
export function createJWTAuthHandler<AuthedUserData>(
  options: JWTAuthHandlerOptions
): AuthHandler<AuthedUserData> {
  if (!jwt) throw new Error("jwt not found");
  return (req) => {
    let token: string;
    if (options.tokenSource === "header") {
      let headerName = options.headerName;
      if (!headerName) {
        headerName = "authorization";
      }
      let header = req.headers[headerName];
      if (!header) throw new HTTPError(401, "no token provided");
      if (Array.isArray(header)) throw new HTTPError(401, "invalid token");

      let headerSplit = header.split(" ")[1];
      if (!headerSplit) throw new HTTPError(401, "invalid token");
      token = headerSplit;
    } else if (options.tokenSource === "cookie") {
      let cookieName = options.cookieName;
      if (!cookieName) {
        cookieName = "auth_token";
      }
      if (!req.cookies)
        throw new Error(
          "the cookies field does not exist on the request, probably because you didn't add the cookie-parser middleware"
        );
      let cookie: string | undefined = req.cookies[cookieName];
      if (!cookie) throw new HTTPError(401, "no token provided");
      token = cookie;
    }
    return new Promise((resolve, reject) => {
      jwt.verify(token, options.auth_secret, (err, user) => {
        if (err) reject(new HTTPError(401, "invalid token"));
        resolve(user as AuthedUserData);
      });
    });
  };
}
