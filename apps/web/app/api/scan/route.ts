import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { target, type } = await request.json();
    
    // Simulate deep static analysis delay (1.5 seconds)
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const isUrl = type === "url";
    const name = isUrl ? target.split("/").pop() || "unknown-model" : target;
    const isPickle = name.endsWith(".pt") || name.endsWith(".bin") || name.endsWith(".pkl");
    const isSafeTensor = name.endsWith(".safetensors") || name.endsWith(".gguf");

    let risk: "None" | "Low" | "High" | "Critical" = "Low";
    let status: "Verified" | "Quarantined" | "Flagged" = "Flagged";
    let clean = false;
    let format = isSafeTensor ? (name.endsWith(".gguf") ? "GGUF" : "Safetensors") : isPickle ? "PyTorch (Pickle)" : "Unknown/Raw";

    // Logic: .pt files are inherently risky due to arbitrary code execution in Pickle
    if (isPickle) {
      risk = "High";
      status = "Quarantined";
      clean = false;
    } else if (isSafeTensor) {
      risk = "None";
      status = "Verified";
      clean = true;
    } else {
      risk = "Low";
      status = "Flagged";
      clean = false;
    }

    const result = {
      id: Math.random().toString(36).substring(7),
      name,
      type: format,
      risk,
      status,
      clean,
      timestamp: Date.now()
    };

    return NextResponse.json({ success: true, result });
  } catch (error) {
    return NextResponse.json({ success: false, error: "Analysis failed" }, { status: 500 });
  }
}
