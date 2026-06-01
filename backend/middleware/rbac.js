/**
 * Helper to check if the active user matches the target resource owner.
 */
export const isSelf = (user, targetUid) => {
  return user && user.uid === targetUid;
};

/**
 * Dynamic OU authorization helper.
 * A user can manage a target OU if they are a SUPER_ADMIN,
 * or if they are an ADMIN and their assigned OU matches the target OU.
 */
export const canManageOU = (user, targetOU) => {
  if (!user) return false;
  if (user.role === 'SUPER_ADMIN') return true;
  
  if (user.role === 'ADMIN' && user.ou && targetOU) {
    return user.ou.toLowerCase().trim() === targetOU.toLowerCase().trim();
  }
  
  return false;
};

/**
 * Express middleware to ensure the user is authorized to perform changes in the target department.
 * Maps parameters dynamically based on keys from request params or body.
 */
export const requireManageOU = (getOUParamName) => {
  return (req, res, next) => {
    const targetOU = req.params[getOUParamName] || req.body[getOUParamName];
    if (!targetOU) {
      return res.status(400).json({ message: 'Target department/OU is required' });
    }

    if (canManageOU(req.user, targetOU)) {
      return next();
    }

    return res.status(403).json({ 
      message: `Access denied. You do not have permissions to manage the "${targetOU}" department.` 
    });
  };
};

/**
 * Express middleware to ensure a user is either acting on their own profile (self-service)
 * or is an authorized department admin / superadmin for the target profile's department.
 */
export const requireSelfOrAdmin = (getUidParamName, getOUParamName) => {
  return (req, res, next) => {
    const targetUid = req.params[getUidParamName] || req.body[getUidParamName];
    // If target OU isn't directly passed, we'll try to find it on req.body, or allow next step to validate it.
    const targetOU = req.params[getOUParamName] || req.body[getOUParamName] || req.body.ou || req.query.ou;

    if (isSelf(req.user, targetUid)) {
      return next();
    }

    if (targetOU && canManageOU(req.user, targetOU)) {
      return next();
    }

    // If targetOU was not provided, but they are a superadmin, allow it anyway.
    if (req.user.role === 'SUPER_ADMIN') {
      return next();
    }

    return res.status(403).json({
      message: 'Access denied. You can only manage your own profile or users inside your assigned department.'
    });
  };
};
