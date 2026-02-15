import { useState } from "react";
import api from "../api/axios";
import "../styles/upload.css";

function UserFileUpload() {

  const [file, setFile] = useState(null);

  const [message, setMessage] = useState("");

  const [error, setError] = useState("");

  const [uploading, setUploading] = useState(false);

  const [progress, setProgress] = useState(0);

  const [dragActive, setDragActive] = useState(false);


  /* =========================
     FILE SELECTION
  ========================= */

  const handleFileChange = (e) => {

    setFile(e.target.files[0]);

    setMessage("");
    setError("");
  };


  /* =========================
     DRAG EVENTS
  ========================= */

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

    const droppedFile = e.dataTransfer.files[0];

    if (droppedFile) {

      setFile(droppedFile);

      setMessage("");
      setError("");
    }
  };


  /* =========================
     UPLOAD FUNCTION
  ========================= */

  const handleUpload = async () => {

    if (!file) {

      setError("Please select a file");

      return;
    }

    const formData = new FormData();

    formData.append("file", file);

    try {

      setUploading(true);

      setProgress(0);

      setMessage("");

      setError("");

      const response = await api.post(

        "/files/upload",

        formData,

        {

          headers: {
            "Content-Type": "multipart/form-data",
          },

          onUploadProgress: (event) => {

            const percent = Math.round(

              (event.loaded * 100) / event.total

            );

            setProgress(percent);
          },

        }

      );

      /*
      =========================
      SAFE FILE RESPONSE
      =========================
      */

      setMessage(

        response.data.message ||
        "File uploaded securely and malware-free ✅"

      );

      setFile(null);

    } catch (err) {

      /*
      =========================
      MALWARE DETECTED RESPONSE
      =========================
      */

      if (err.response?.data?.message) {

        if (

          err.response.data.message.includes("Malware")

        ) {

          setError(

            "🚫 Malware detected! Upload blocked for security."

          );

        }

        else {

          setError(err.response.data.message);
        }

      }

      else {

        setError("Upload failed. Please try again.");
      }

    }

    finally {

      setUploading(false);

      setProgress(0);
    }
  };


  /* =========================
     UI
  ========================= */

  return (

    <div className="upload-page">

      <div className="upload-card">

        <h2 className="upload-title">

          🔐 Secure File Upload

        </h2>


        {/* DROP ZONE */}

        <div

          className={`drop-zone ${dragActive ? "active" : ""}`}

          onDragOver={handleDragOver}

          onDragLeave={handleDragLeave}

          onDrop={handleDrop}

        >

          {file ? (

            <p>📄 {file.name}</p>

          ) : (

            <p>

              Drag & drop a file here or click to select

            </p>

          )}

          <input

            type="file"

            onChange={handleFileChange}

          />

        </div>


        {/* UPLOAD BUTTON */}

        <button

          className="upload-btn"

          onClick={handleUpload}

          disabled={uploading}

        >

          {uploading

            ? "Scanning & Uploading..."

            : "Upload Securely"}

        </button>


        {/* PROGRESS BAR */}

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


        {/* SUCCESS MESSAGE */}

        {message && (

          <p

            className="upload-message"

            style={{ color: "limegreen" }}

          >

            {message}

          </p>

        )}


        {/* ERROR MESSAGE */}

        {error && (

          <p

            className="upload-message"

            style={{ color: "red" }}

          >

            {error}

          </p>

        )}

      </div>

    </div>
  );
}

export default UserFileUpload;
