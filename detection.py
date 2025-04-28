rom PIL import Image
import numpy as np
import os
import math


def analyze_histogram(image_path):
    img = Image.open(image_path)
    histogram = np.array(img.histogram())
    variance = np.var(histogram)
    return variance

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        byte_arr = list(f.read())
    file_size = len(byte_arr)
    freq_list = []
    
    for b in range(256):
        ctr = byte_arr.count(b)
        freq_list.append(float(ctr) / file_size)
    
    entropy = 0.0
    for freq in freq_list:
        if freq > 0:
            entropy += freq * math.log(freq, 2)
    entropy = -entropy
    return entropy


def detect_image(image_path, hist_threshold=100000, entropy_threshold=7.95):
    variance = analyze_histogram(image_path)
    entropy = calculate_entropy(image_path)

    if variance > hist_threshold or entropy > entropy_threshold:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
return variance, entropy, verdict


if __name__ == "__main__":
    folder = input("ENTER FOLDER PATH TO SCAN (ex:clean/): ").strip()
    output_file = input("Enter filename to save results (example: results.txt): ").strip()

    results = []
    suspicious_count = 0
    clean_count = 0

    print(f"[*] Scanning all images inside {folder}...\n")
    print("{:<40} {:<15} {:<15}".format("Filename", "Variance", "Entropy", "Result"))
    print("-" * 90)

    for filename in os.listdir(folder):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            path = os.path.join(folder, filename)
            variance, entropy, verdict = detect_image(path)
            print("{:<40} {:<15.2f} {:<15.4f} {:<15}".format(filename, variance, entropy, verdict))
            results.append((filename, variance, entropy, verdict))

            # Count based on result
            if verdict == "Suspicious":
                suspicious_count += 1
            else:
                clean_count += 1

    # Save results to file
    with open(output_file, 'w') as f:
        f.write("{:<40} {:<15} {:<15} {:<15}\n".format("Filename", "Variance", "Entropy", "Result"))
        f.write("-" * 90 + "\n")
        for entry in results:
            f.write("{:<40} {:<15.2f} {:<15.4f} {:<15}\n".format(entry[0], entry[1], entry[2], entry[3]))

    print(f"\n[+] Scan complete. Results saved to {output_file}")
  
# Print Final Summary
    total_images = suspicious_count + clean_count
    print("\n[*] Scan Summary:")
    print(f"Total Images Scanned: {total_images}")
    print(f"Clean Images Detected: {clean_count}")
    print(f"Suspicious Images Detected: {suspicious_count}")

    if total_images > 0:
        detection_rate = (suspicious_count / total_images) * 100
        print(f"Detection Rate (Suspicious Files): {detection_rate:.2f}%")
    else:
        print("No images found to scan.")

    print(f"\n[+] Scan complete. Results saved to {output_file}")
