import crypto from "crypto";
import fs from "fs";

const algorithm = "aes-256-gcm";

/* ===============================
   GET SECRET KEY SAFELY
=============================== */
const getSecretKey = () => {

  if (!process.env.FILE_SECRET) {

    throw new Error(
      "FILE_SECRET is missing. Set it in backend/.env and restart server."
    );

  }

  return crypto
    .createHash("sha256")
    .update(process.env.FILE_SECRET)
    .digest();
};


/* ===============================
   ENCRYPT FILE (AES-256-GCM)
=============================== */
export const encryptFile = (inputPath, outputPath) => {

  return new Promise((resolve, reject) => {

    try {

      const key = getSecretKey();

      const iv = crypto.randomBytes(12); // GCM standard IV size

      const cipher = crypto.createCipheriv(
        algorithm,
        key,
        iv
      );

      const input = fs.createReadStream(inputPath);
      const output = fs.createWriteStream(outputPath);

      // Write IV first
      output.write(iv);

      input
        .pipe(cipher)
        .pipe(output);

      output.on("finish", () => {

        try {

          const authTag = cipher.getAuthTag();

          // Append auth tag at end
          fs.appendFileSync(outputPath, authTag);

          resolve();

        } catch (err) {

          reject(err);

        }

      });

      output.on("error", reject);

    }
    catch (err) {

      reject(err);

    }

  });

};


/* ===============================
   DECRYPT FILE (AES-256-GCM)
=============================== */
export const decryptFile = (inputPath, outputPath) => {

  return new Promise((resolve, reject) => {

    try {

      const key = getSecretKey();

      const fileBuffer = fs.readFileSync(inputPath);

      const iv = fileBuffer.slice(0, 12);

      const authTag = fileBuffer.slice(fileBuffer.length - 16);

      const encryptedData =
        fileBuffer.slice(12, fileBuffer.length - 16);

      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        iv
      );

      decipher.setAuthTag(authTag);

      const decrypted =
        Buffer.concat([
          decipher.update(encryptedData),
          decipher.final()
        ]);

      fs.writeFileSync(outputPath, decrypted);

      resolve();

    }
    catch (err) {

      reject(err);

    }

  });

};
