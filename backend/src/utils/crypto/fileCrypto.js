import crypto from "crypto";
import fs from "fs";

const algorithm = "aes-256-cbc";

/* ===============================
   GET SECRET KEY SAFELY (RUNTIME)
   =============================== */
const getSecretKey = () => {
  if (!process.env.FILE_SECRET) {
    throw new Error(
      "FILE_SECRET is missing. Set it in backend/.env and restart server."
    );
  }

  return crypto
    .createHash("sha256")
    .update(String(process.env.FILE_SECRET))
    .digest();
};

/* ===============================
   ENCRYPT FILE
   =============================== */
export const encryptFile = (inputPath, outputPath) => {
  return new Promise((resolve, reject) => {
    try {
      const secretKey = getSecretKey();
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(
        algorithm,
        secretKey,
        iv
      );

      const input = fs.createReadStream(inputPath);
      const output = fs.createWriteStream(outputPath);

      // Store IV at beginning of file
      output.write(iv);

      input
        .pipe(cipher)
        .pipe(output)
        .on("finish", resolve)
        .on("error", reject);
    } catch (err) {
      reject(err);
    }
  });
};

/* ===============================
   DECRYPT FILE
   =============================== */
export const decryptFile = (inputPath, outputPath) => {
  return new Promise((resolve, reject) => {
    try {
      const secretKey = getSecretKey();

      // Read IV (first 16 bytes)
      const iv = Buffer.alloc(16);
      const fd = fs.openSync(inputPath, "r");
      fs.readSync(fd, iv, 0, 16, 0);
      fs.closeSync(fd);

      const decipher = crypto.createDecipheriv(
        algorithm,
        secretKey,
        iv
      );

      const input = fs.createReadStream(inputPath, { start: 16 });
      const output = fs.createWriteStream(outputPath);

      input
        .pipe(decipher)
        .pipe(output)
        .on("finish", resolve)
        .on("error", reject);
    } catch (err) {
      reject(err);
    }
  });
};
