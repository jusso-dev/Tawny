type UserWithRole = {
  role?: string | null;
};

export function authRole(user: UserWithRole) {
  return user.role === "Viewer" ? "Viewer" : "Admin";
}
