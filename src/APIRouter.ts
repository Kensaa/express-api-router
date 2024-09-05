import { Router } from "express";
import { z } from "zod";
import type {
  Router as RouterType,
  Request as ExpressRequest,
  Response as ExpressResponse,
  NextFunction as ExpressNextFunction,
} from "express";
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

export function createJWTAuthHandler<AuthedUserData>(
  AUTH_SECRET: string
): AuthHandler<AuthedUserData> {
  if (!jwt) throw new Error("jwt not found");
  return (req) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.split(" ")[1];
      if (!token) throw new HTTPError(401, "no token provided");

      return new Promise((res, rej) => {
        jwt.verify(token, AUTH_SECRET, (err, user) => {
          if (err) rej(new HTTPError(401, "invalid token"));
          res(user as AuthedUserData);
        });
      });
    } else {
      throw new HTTPError(401, "no token provided");
    }
  };
}
