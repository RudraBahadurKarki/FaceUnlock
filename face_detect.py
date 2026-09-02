import cv2
import os

MODEL = "face_detection_yunet_2023mar.onnx"

if not os.path.exists(MODEL):
    print("ERROR: Face detector model not found.")
    print(f"Expected: {os.path.abspath(MODEL)}")
    exit()

detector = cv2.FaceDetectorYN.create(
    MODEL,
    "",
    (320, 320),
    0.9,
    0.3,
    5000
)

camera = cv2.VideoCapture(0)

if not camera.isOpened():
    print("ERROR: Could not open camera.")
    exit()

print("FaceUnlock face detector started.")
print("Press Q to quit.")

while True:
    ret, frame = camera.read()

    if not ret:
        print("ERROR: Could not read camera.")
        break

    height, width = frame.shape[:2]

    detector.setInputSize((width, height))

    _, faces = detector.detect(frame)

    if faces is not None:
        for face in faces:
            x, y, w, h = face[:4].astype(int)

            cv2.rectangle(
                frame,
                (x, y),
                (x + w, y + h),
                (0, 255, 0),
                2
            )

            cv2.putText(
                frame,
                "FACE DETECTED",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 0),
                2
            )

    cv2.imshow("FaceUnlock - Face Detection", frame)

    if cv2.waitKey(1) & 0xFF == ord("q"):
        break

camera.release()
cv2.destroyAllWindows()