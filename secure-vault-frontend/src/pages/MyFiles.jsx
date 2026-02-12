import { useEffect, useState } from "react";
import api from "../api/axios";
import "../styles/myfiles.css";

function MyFiles() {
  const [files, setFiles] = useState([]);
  const [filteredFiles, setFilteredFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Search & filter states
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sortBy, setSortBy] = useState("date");

  useEffect(() => {
    fetchFiles();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [search, typeFilter, sortBy, files]);

  /* =========================
     FETCH FILES
  ========================= */
  const fetchFiles = async () => {
    try {
      const res = await api.get("/files/my-files");
      setFiles(res.data);
      setFilteredFiles(res.data);
    } catch {
      setError("Failed to load files");
    } finally {
      setLoading(false);
    }
  };

  /* =========================
     APPLY SEARCH & FILTER
  ========================= */
  const applyFilters = () => {
    let data = [...files];

    if (search) {
      data = data.filter((file) =>
        file.original_name
          .toLowerCase()
          .includes(search.toLowerCase())
      );
    }

    if (typeFilter !== "all") {
      data = data.filter((file) =>
        file.mime_type.startsWith(typeFilter)
      );
    }

    if (sortBy === "date") {
      data.sort(
        (a, b) =>
          new Date(b.created_at) -
          new Date(a.created_at)
      );
    } else if (sortBy === "size") {
      data.sort((a, b) => b.file_size - a.file_size);
    }

    setFilteredFiles(data);
  };

  /* =========================
     PREVIEW
  ========================= */
  const handlePreview = async (fileId, mimeType) => {
    try {
      const res = await api.get(
        `/files/preview/${fileId}`,
        { responseType: "blob" }
      );

      const blob = new Blob([res.data], {
        type: mimeType,
      });

      const url = window.URL.createObjectURL(blob);

      window.open(url, "_blank");

      setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 5000);

    } catch {
      alert("Preview failed");
    }
  };

  /* =========================
     DOWNLOAD
  ========================= */
  const handleDownload = async (fileId, fileName) => {
    try {
      const res = await api.get(
        `/files/download/${fileId}`,
        { responseType: "blob" }
      );

      const url = window.URL.createObjectURL(
        new Blob([res.data])
      );

      const link = document.createElement("a");
      link.href = url;
      link.download = fileName;
      link.click();

      window.URL.revokeObjectURL(url);
    } catch {
      alert("Download failed");
    }
  };

  /* =========================
     DELETE
  ========================= */
  const handleDelete = async (fileId) => {
    if (!window.confirm("Delete this file permanently?"))
      return;

    try {
      await api.delete(`/files/delete/${fileId}`);
      setFiles((prev) =>
        prev.filter((f) => f.id !== fileId)
      );
    } catch {
      alert("Delete failed");
    }
  };

  return (
    <div className="myfiles-container">

      {/* Header */}
      <div className="myfiles-header">
        <h2 className="myfiles-title">📂 Secure Vault Files</h2>
        <p className="myfiles-subtitle">
          Manage, preview, and protect your encrypted files
        </p>
      </div>

      {/* Controls */}
      <div className="myfiles-controls">

        <input
          className="myfiles-input"
          type="text"
          placeholder="🔍 Search files..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <select
          className="myfiles-select"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="all">All Types</option>
          <option value="image">Images</option>
          <option value="application">Documents</option>
        </select>

        <select
          className="myfiles-select"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="date">Newest First</option>
          <option value="size">Largest First</option>
        </select>

      </div>

      {/* Status */}
      {loading && (
        <p className="myfiles-status">Loading secure files...</p>
      )}

      {error && (
        <p className="myfiles-error">{error}</p>
      )}

      {!loading && filteredFiles.length === 0 && (
        <p className="myfiles-status">No secure files found.</p>
      )}

      {/* Table */}
      {filteredFiles.length > 0 && (
        <div className="myfiles-table-wrapper">

          <table className="myfiles-table">

            <thead>
              <tr>
                <th>File Name</th>
                <th>Type</th>
                <th>Size</th>
                <th>Uploaded</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>

              {filteredFiles.map((file) => (

                <tr key={file.id}>

                  <td className="file-name">
                    {file.original_name}
                  </td>

                  <td>
                    <span className="file-type-badge">
                      {file.mime_type}
                    </span>
                  </td>

                  <td>
                    {(file.file_size / 1024).toFixed(2)} KB
                  </td>

                  <td>
                    {new Date(
                      file.created_at
                    ).toLocaleString()}
                  </td>

                  <td>

                    <div className="file-actions">

                      <button
                        className="btn-preview"
                        onClick={() =>
                          handlePreview(
                            file.id,
                            file.mime_type
                          )
                        }
                      >
                        👁 Preview
                      </button>

                      <button
                        className="btn-download"
                        onClick={() =>
                          handleDownload(
                            file.id,
                            file.original_name
                          )
                        }
                      >
                        ⬇ Download
                      </button>

                      <button
                        className="btn-delete"
                        onClick={() =>
                          handleDelete(file.id)
                        }
                      >
                        🗑 Delete
                      </button>

                    </div>

                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>
      )}

    </div>
  );
}

export default MyFiles;
