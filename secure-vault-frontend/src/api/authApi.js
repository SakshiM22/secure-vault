import api from "./axios";

/* =========================
   LOGIN API (ROLE BASED)
========================= */
export const loginUser = async (email, password, role) => {

  const response = await api.post(
    "/auth/login",
    {
      email,
      password,
      role   // CRITICAL FIX
    }
  );

  return response.data;

};


/* =========================
   SIGNUP API
========================= */
export const signupUser = async (email, password) => {

  const response = await api.post(
    "/auth/signup",
    {
      email,
      password
    }
  );

  return response.data;

};
