import { Router } from "express";
import { z } from "zod";
import type {
  Router as RouterType,
  Request as ExpressRequest,
  Response as ExpressResponse,
  NextFunction as ExpressNextFunction,
} from "express";
import type { IncomingHttpHeaders } from "http";
import jwt from "jsonwebtoken";

type HTTPMethod = "get" | "post" | "put" | "delete";
interface Queries {
  [key: string]: undefined | string | string[] | Queries | Queries[];
}
type ZAny = z.ZodTypeAny;

export interface Request<
  QueryType extends Queries = Queries,
  BodyType = Record<string, unknown>,
  ParamType extends Record<string, string> = Record<string, string>
> extends ExpressRequest {
  query: QueryType;
  body: BodyType;
  params: ParamType;
}

export type Response = ExpressResponse;
export type NextFunction = ExpressNextFunction;

/**
 * A function that extracts user data from a request.
 * @param req The {@link Request} object
 * @returns User data
 *
 * @throws Throws {@link HTTPError} if the user is not authenticated
 */
export type AuthHandler<AuthedUserData> = (
  req: Request
) => AuthedUserData | Promise<AuthedUserData>;

export type RouteHandler<
  BodySchema extends ZAny,
  QuerySchema extends ZAny,
  ParamSchema extends ZAny,
  ResponseSchema extends ZAny,
  Instances,
  AuthedUserData
> = {
  bodySchema: BodySchema;
  querySchema: QuerySchema;
  paramsSchema: ParamSchema;
  responseSchema: ResponseSchema;
} & (
  | {
      authed: true;
      handler: (
        req: Request<
          z.infer<QuerySchema>,
          z.infer<BodySchema>,
          z.infer<ParamSchema>
        >,
        instances: Instances,
        userTokenData: AuthedUserData
      ) => z.infer<ResponseSchema> | Promise<z.infer<ResponseSchema>>;
    }
  | {
      authed: false;
      handler: (
        req: Request<
          z.infer<QuerySchema>,
          z.infer<BodySchema>,
          z.infer<ParamSchema>
        >,
        instances: Instances
      ) => z.infer<ResponseSchema> | Promise<z.infer<ResponseSchema>>;
    }
);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function errorMiddleware(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (err instanceof HTTPError) {
    err.sendError(res);
  } else if (err instanceof z.ZodError) {
    res.status(400).json(err.errors);
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
    BodySchema extends ZAny,
    QuerySchema extends ZAny,
    ParamSchema extends ZAny,
    ResponseSchema extends ZAny
  >(
    routeHandler: RouteHandler<
      BodySchema,
      QuerySchema,
      ParamSchema,
      ResponseSchema,
      InstanceType,
      AuthedUserData
    >
  ): RouteHandler<
    BodySchema,
    QuerySchema,
    ParamSchema,
    ResponseSchema,
    InstanceType,
    AuthedUserData
  > {
    return routeHandler;
  }

  registerRoute<
    BodySchema extends ZAny,
    QuerySchema extends ZAny,
    ParamSchema extends ZAny,
    ResponseSchema extends ZAny
  >(
    method: HTTPMethod,
    path: string,
    routeHandler: RouteHandler<
      BodySchema,
      QuerySchema,
      ParamSchema,
      ResponseSchema,
      InstanceType,
      AuthedUserData
    >
  ) {
    const handlers: ((
      req: Request,
      res: Response,
      next: NextFunction
    ) => void)[] = [];

    let userTokenData: AuthedUserData | undefined;
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
          userTokenData =
            authResult instanceof Promise ? await authResult : authResult;
          next();
        } catch (err) {
          next(err);
        }
      });
    }

    // Input validation
    handlers.push((req, res, next) => {
      req.query = routeHandler.querySchema.parse(req.query);
      req.body = routeHandler.bodySchema.parse(req.body);
      req.params = routeHandler.paramsSchema.parse(req.params);
      next();
    });

    // Route handler
    handlers.push(async (req, res, next) => {
      try {
        let handlerResult;

        if (routeHandler.authed) {
          handlerResult = routeHandler.handler(
            req,
            this.instances,
            userTokenData!
          );
        } else {
          handlerResult = routeHandler.handler(req, this.instances);
        }

        const result =
          handlerResult instanceof Promise
            ? await handlerResult
            : handlerResult;

        const parsedResult = routeHandler.responseSchema.parse(result);
        res.status(200).json(parsedResult);
      } catch (err) {
        next(err);
      }
    });

    this.router[method](path, ...handlers, errorMiddleware);
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
