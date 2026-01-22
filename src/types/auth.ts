export type UserRole = "OWNER" | "PRINCIPAL" | "TEACHER" | "PARENT" | "STUDENT";

export interface UserPermissions {
  canManageUsers: boolean;
  canManageStudents: boolean;
  canManageTeachers: boolean;
  canManageParents: boolean;
  canManageClasses: boolean;
  canManageMaterials: boolean;
  canManageSchedules: boolean;
  canManageAttendance: boolean;
  canViewReports: boolean;
  canManageSystem: boolean;
  canManageMessages: boolean;
  canManagePrincipals: boolean;
}

export const ROLE_PERMISSIONS: Record<UserRole, UserPermissions> = {
  OWNER: {
    canManageUsers: true,
    canManageStudents: true,
    canManageTeachers: true,
    canManageParents: true,
    canManageClasses: true,
    canManageMaterials: true,
    canManageSchedules: true,
    canManageAttendance: true,
    canViewReports: true,
    canManageSystem: true,
    canManageMessages: true,
    canManagePrincipals: true,
  },
  PRINCIPAL: {
    canManageUsers: false,
    canManageStudents: true,
    canManageTeachers: true,
    canManageParents: true,
    canManagePrincipals: false,
    canManageClasses: true,
    canManageMaterials: true,
    canManageSchedules: true,
    canManageAttendance: true,
    canViewReports: true,
    canManageSystem: false,
    canManageMessages: true,
  },
  TEACHER: {
    canManageUsers: false,
    canManageStudents: false,
    canManageTeachers: false,
    canManageParents: false,
    canManagePrincipals: false,
    canManageClasses: false,
    canManageMaterials: true,
    canManageSchedules: false,
    canManageAttendance: true,
    canViewReports: false,
    canManageSystem: false,
    canManageMessages: true,
  },
  PARENT: {
    canManageUsers: false,
    canManageStudents: false,
    canManageTeachers: false,
    canManageParents: false,
    canManagePrincipals: false,
    canManageClasses: false,
    canManageMaterials: false,
    canManageSchedules: false,
    canManageAttendance: false,
    canViewReports: true,
    canManageSystem: false,
    canManageMessages: true,
  },
  STUDENT: {
    canManageUsers: false,
    canManageStudents: false,
    canManageTeachers: false,
    canManageParents: false,
    canManagePrincipals: false,
    canManageClasses: false,
    canManageMaterials: false,
    canManageSchedules: false,
    canManageAttendance: false,
    canViewReports: false,
    canManageSystem: false,
    canManageMessages: true,
  },
};

export const ROLE_HIERARCHY: UserRole[] = [
  "OWNER",
  "PRINCIPAL",
  "TEACHER",
  "PARENT",
  "STUDENT",
];

export function hasPermission(
  role: UserRole,
  permission: keyof UserPermissions,
): boolean {
  return ROLE_PERMISSIONS[role]?.[permission] || false;
}

export function hasRoleAccess(
  userRole: UserRole,
  requiredRoles: UserRole[],
): boolean {
  return requiredRoles.includes(userRole);
}

export function getRoleLevel(role: UserRole): number {
  return ROLE_HIERARCHY.indexOf(role);
}

export function isRoleHigherOrEqual(
  userRole: UserRole,
  targetRole: UserRole,
): boolean {
  return getRoleLevel(userRole) <= getRoleLevel(targetRole);
}
