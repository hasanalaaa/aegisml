"use client";
import { motion } from "framer-motion";

interface RevealTextProps {
  children: string;
  className?: string;
  style?: React.CSSProperties;
  delay?: number;
}

export default function RevealText({ children, className, style, delay = 0 }: RevealTextProps) {
  const words = children.split(" ");

  return (
    <span className={className} style={{ display: "inline-block", overflow: "hidden", ...style }}>
      {words.map((word, i) => (
        <motion.span
          key={i}
          initial={{ opacity: 0, y: "100%" }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{
            duration: 0.8,
            delay: delay + i * 0.05,
            ease: [0.215, 0.61, 0.355, 1],
          }}
          style={{ display: "inline-block", marginLeft: "0.3em" }}
        >
          {word}
        </motion.span>
      ))}
    </span>
  );
}
