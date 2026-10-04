type UserWithRole = {
  role?: string | null;
};

// Fail closed: only an explicit "Admin" grants admin rights.
export function authRole(user: UserWithRole) {
  return user.role === "Admin" ? "Admin" : "Viewer";
}
