import { useState } from "react";
import api from "../api/axios";
import "../styles/upload.css";

function UserFileUpload() {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragActive(true);
  };

  const handleDragLeave = () => {
    setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    setFile(e.dataTransfer.files[0]);
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a file");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      setUploading(true);
      setProgress(0);
      setMessage("");

      await api.post("/files/upload", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
        onUploadProgress: (event) => {
          const percent = Math.round(
            (event.loaded * 100) / event.total
          );
          setProgress(percent);
        },
      });

      setMessage("File uploaded securely ✅");
      setFile(null);
    } catch {
      setMessage("Upload failed ❌");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="upload-page">
      <div className="upload-card">
        <h2 className="upload-title">🔐 Secure File Upload</h2>

        <div
          className={`drop-zone ${dragActive ? "active" : ""}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {file ? (
            <p>📄 {file.name}</p>
          ) : (
            <p>Drag & drop a file here</p>
          )}

          <input type="file" onChange={handleFileChange} />
        </div>

        <button
          className="upload-btn"
          onClick={handleUpload}
          disabled={uploading}
        >
          {uploading ? "Uploading..." : "Upload"}
        </button>

        {uploading && (
          <div className="progress-wrapper">
            <div className="progress-bar-bg">
              <div
                className="progress-bar-fill"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="progress-text">
              Uploading: {progress}%
            </p>
          </div>
        )}

        {message && (
          <p className="upload-message">{message}</p>
        )}
      </div>
    </div>
  );
}

export default UserFileUpload;
