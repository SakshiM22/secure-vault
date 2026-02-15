import { useEffect, useState } from "react";
import api from "../api/axios";
import "../styles/myfiles.css";

function MyFiles() {

  const [files, setFiles] = useState([]);
  const [filteredFiles, setFilteredFiles] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sortBy, setSortBy] = useState("date");


  /* =========================
     FETCH FILES
  ========================= */

  useEffect(() => {

    fetchFiles();

  }, []);

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
     APPLY FILTERS
  ========================= */

  useEffect(() => {

    applyFilters();

  }, [search, typeFilter, sortBy, files]);

  const applyFilters = () => {

    let data = [...files];

    if (search) {

      data = data.filter(file =>
        file.original_name
          .toLowerCase()
          .includes(search.toLowerCase())
      );
    }

    if (typeFilter !== "all") {

      data = data.filter(file =>
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

      data.sort(
        (a, b) =>
          b.file_size - a.file_size
      );
    }

    setFilteredFiles(data);
  };


  /* =========================
     PREVIEW
  ========================= */

  const handlePreview = async (file) => {

    if (file.malware_status === "MALICIOUS") {

      alert(
        "⚠ Cannot preview malicious file for security reasons."
      );

      return;
    }

    try {

      const res = await api.get(
        `/files/preview/${file.id}`,
        { responseType: "blob" }
      );

      const blob = new Blob(
        [res.data],
        { type: file.mime_type }
      );

      const url =
        window.URL.createObjectURL(blob);

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

  const handleDownload = async (file) => {

    if (file.malware_status === "MALICIOUS") {

      alert(
        "⚠ Download blocked. File contains malware."
      );

      return;
    }

    try {

      const res = await api.get(
        `/files/download/${file.id}`,
        { responseType: "blob" }
      );

      const url =
        window.URL.createObjectURL(
          new Blob([res.data])
        );

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        file.original_name;

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

    if (!window.confirm(
      "Delete this file permanently?"
    )) return;

    try {

      await api.delete(
        `/files/delete/${fileId}`
      );

      setFiles(prev =>
        prev.filter(f =>
          f.id !== fileId
        )
      );

    } catch {

      alert("Delete failed");
    }
  };


  /* =========================
     MALWARE STATUS BADGE
  ========================= */

  const renderStatus = (status) => {

    if (status === "SAFE") {

      return (
        <span
          style={{
            color: "limegreen",
            fontWeight: "bold"
          }}
        >
          SAFE
        </span>
      );
    }

    if (status === "MALICIOUS") {

      return (
        <span
          style={{
            color: "red",
            fontWeight: "bold"
          }}
        >
          MALICIOUS ⚠
        </span>
      );
    }

    return (
      <span>PENDING</span>
    );
  };


  /* =========================
     UI
  ========================= */

  return (

    <div className="myfiles-container">

      <div className="myfiles-header">

        <h2 className="myfiles-title">
          📂 Secure Vault Files
        </h2>

        <p className="myfiles-subtitle">
          Manage, preview, and protect your encrypted files
        </p>

      </div>


      {/* CONTROLS */}

      <div className="myfiles-controls">

        <input
          className="myfiles-input"
          type="text"
          placeholder="🔍 Search files..."
          value={search}
          onChange={(e) =>
            setSearch(e.target.value)
          }
        />

        <select
          className="myfiles-select"
          value={typeFilter}
          onChange={(e) =>
            setTypeFilter(e.target.value)
          }
        >
          <option value="all">All Types</option>
          <option value="image">Images</option>
          <option value="application">Documents</option>
        </select>

        <select
          className="myfiles-select"
          value={sortBy}
          onChange={(e) =>
            setSortBy(e.target.value)
          }
        >
          <option value="date">Newest First</option>
          <option value="size">Largest First</option>
        </select>

      </div>


      {/* STATUS */}

      {loading && (
        <p>Loading secure files...</p>
      )}

      {error && (
        <p className="myfiles-error">
          {error}
        </p>
      )}


      {/* TABLE */}

      {!loading && filteredFiles.length > 0 && (

        <table className="myfiles-table">

          <thead>

            <tr>
              <th>File Name</th>
              <th>Type</th>
              <th>Size</th>
              <th>Status</th>
              <th>Uploaded</th>
              <th>Actions</th>
            </tr>

          </thead>

          <tbody>

            {filteredFiles.map(file => (

              <tr key={file.id}>

                <td>{file.original_name}</td>

                <td>{file.mime_type}</td>

                <td>
                  {(file.file_size / 1024)
                    .toFixed(2)} KB
                </td>

                <td>
                  {renderStatus(
                    file.malware_status
                  )}
                </td>

                <td>
                  {new Date(
                    file.created_at
                  ).toLocaleString()}
                </td>

                <td>

                  <button
                    onClick={() =>
                      handlePreview(file)
                    }
                  >
                    Preview
                  </button>

                  <button
                    onClick={() =>
                      handleDownload(file)
                    }
                  >
                    Download
                  </button>

                  <button
                    onClick={() =>
                      handleDelete(file.id)
                    }
                  >
                    Delete
                  </button>

                </td>

              </tr>

            ))}

          </tbody>

        </table>

      )}

    </div>
  );
}

export default MyFiles;
