export function checkPasswordStrength(password = "") {
  let score = 0;

  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 1) {
    return { label: "Weak", color: "red" };
  }

  if (score === 2) {
    return { label: "Medium", color: "orange" };
  }

  return { label: "Strong", color: "green" };
}
