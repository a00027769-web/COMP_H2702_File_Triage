import sys
import os
import csv
import hashlib
from datetime import datetime


def calculate_hash(filename):
    with open(filename, "rb") as file:
        content = file.read()
    return hashlib.sha256(content).hexdigest()



def load_references():
    references = {}

    try:
        with open("hashes_reference.csv", "r", newline="") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames or not {"sha256", "label"}.issubset(reader.fieldnames):
                print("Error: Invalid reference CSV columns.")
                return None

            for row in reader:
                file_hash = row["sha256"].strip().lower()
                label = row["label"]

                if len(file_hash) != 64 or any(
                    character not in "0123456789abcdef"
                    for character in file_hash
                ):
                    print("Warning: Invalid SHA-256 reference skipped.")
                    continue

                references[file_hash] = label

    except (OSError, csv.Error, UnicodeError, ValueError) as error:
        print("Error loading references:", error)
        return None

    return references




def analyse_files(folder, references):
    results = []
    hashes = {}

    try:
        filenames = sorted(os.listdir(folder))
    except OSError as error:
        print("Error opening folder:", error)
        return results, hashes

   
    for filename in filenames:
        if not filename.lower().endswith((".txt", ".bin")):
            continue

        if filename == "README.txt":
            continue

        path = os.path.join(folder, filename)

        try:
            if not os.path.isfile(path):
                continue

            file_hash = calculate_hash(path)
            file_size = os.path.getsize(path)
            modified = os.path.getmtime(path)

            if file_hash in references:
                status = "KNOWN"
            else:
                status = "UNKNOWN"

            result = {
                "filename": filename,
                "extension": os.path.splitext(filename)[1],
                "size": file_size,
                "modified": datetime.fromtimestamp(
                    modified
                ).isoformat(timespec="seconds"),
                "sha256": file_hash,
                "status": status
            }

            results.append(result)

            if file_hash not in hashes:
                hashes[file_hash] = []

            hashes[file_hash].append(filename)

        except (OSError, ValueError) as error:
            print("Error reading", filename, ":", error)

    return results, hashes



def generate_report(results, hashes):
    print("\nFILE TRIAGE REPORT")
    print("========================")

    for result in results:
        print("\nFile:", result["filename"])
        print("Extension:", result["extension"])
        print("Size:", result["size"], "bytes")
        print("Modified:", result["modified"])
        print("SHA-256:", result["sha256"])
        print("Status:", result["status"])

    print("\nDUPLICATE FILES")
    print("========================")

    found_duplicate = False

    for file_hash, filenames in hashes.items():
        if len(filenames) > 1:
            found_duplicate = True
            print("Identical files:", ", ".join(filenames))
            print("SHA-256:", file_hash)

    if not found_duplicate:
        print("No duplicates found.")

    try:
        with open("triage_report.csv", "w", newline="") as file:
            fieldnames = [
                "filename", "extension", "size",
                "modified", "sha256", "status"
            ]

            writer = csv.DictWriter(
                file, fieldnames=fieldnames
            )
            writer.writeheader()
            writer.writerows(results)

        print("\nReport saved: triage_report.csv")

    except OSError as error:
        print("Error saving report:", error)



def main():
    if len(sys.argv) > 1:
        folder = sys.argv[1]
    else:
        folder = "."

    if not os.path.isdir(folder):
        print("Error: Folder does not exist:", folder)
        return

    references = load_references()

    if references is None:
        print("Cannot continue without valid reference data.")
        return

    results, hashes = analyse_files(folder, references)

    if not results:
        print("No sample files were successfully analysed.")
        return

    generate_report(results, hashes)


if __name__ == "__main__":
    main()

