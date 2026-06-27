import Navbar from "@/components/Navbar";
import { DeveloperConsoleClient } from "@/components/DeveloperConsoleClient";

export default function DeveloperPage() {
  return (
    <div className="min-h-screen flex flex-col bg-[#0B0B0C] text-gray-100">
      <Navbar />
      <DeveloperConsoleClient />
    </div>
  );
}
