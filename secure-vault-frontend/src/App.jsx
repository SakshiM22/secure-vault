import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import LoginPage from "./pages/LoginPage";
import SignupPage from "./pages/SignupPage";
import ProtectedRoute from "./components/common/ProtectedRoute";
import AccountLocked from "./components/auth/AccountLocked";

import AdminAuditDashboard from "./pages/AdminAuditDashboard";
import UserDashboard from "./pages/UserDashboard";
import UserFileUpload from "./pages/UserFileUpload";
import MyFiles from "./pages/MyFiles";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/account-locked" element={<AccountLocked />} />
        <Route path="/" element={<Home />} />

        {/* User dashboard */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <UserDashboard />
            </ProtectedRoute>
          }
        />

        {/* User file upload */}
        <Route
          path="/upload"
          element={
            <ProtectedRoute>
              <UserFileUpload />
            </ProtectedRoute>
          }
        />

        {/* My files */}
        <Route
          path="/my-files"
          element={
            <ProtectedRoute>
              <MyFiles />
            </ProtectedRoute>
          }
        />

        {/* Admin audit dashboard */}
        <Route
          path="/admin/audit-logs"
          element={
            <ProtectedRoute allowedRoles={["admin"]}>
              <AdminAuditDashboard />
            </ProtectedRoute>
          }
        />

        {/* Default redirect */}
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
