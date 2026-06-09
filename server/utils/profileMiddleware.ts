import { Permission } from '@server/lib/permissions';

export const isOwnProfile = (): Middleware => {
  return (req, res, next) => {
    const targetId = Number(req.params.id ?? req.params.userId);
    if (req.user?.id !== targetId) {
      return next({
        status: 403,
        message: "You do not have permission to view this user's settings.",
      });
    }
    next();
  };
};

export const isOwnProfileOrAdmin = (): Middleware => {
  const authMiddleware: Middleware = (req, res, next) => {
    const targetId = Number(req.params.id ?? req.params.userId);
    if (
      !req.user?.hasPermission(Permission.MANAGE_USERS) &&
      req.user?.id !== targetId
    ) {
      return next({
        status: 403,
        message: "You do not have permission to view this user's settings.",
      });
    }
    next();
  };
  return authMiddleware;
};
