import api from "./axios";

/* =========================
   LOGIN API
   ========================= */
export const loginUser = async (email, password) => {
  const response = await api.post("/auth/login", {
    email,
    password,
  });
  return response.data;
};

/* =========================
   SIGNUP API
   ========================= */
export const signupUser = async (email, password) => {
  const response = await api.post("/auth/signup", {
    email,
    password,
  });
  return response.data;
};
