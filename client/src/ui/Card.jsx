import { motion, useReducedMotion } from "framer-motion";
import { cn } from "../dashboard/dashboardUtils";
import { createEnterMotion, createInteractiveMotion } from "./motionSystem";

export default function Card({
  children,
  className = "",
  hoverable = false,
  delay = 0,
  as = "section",
  ...rest
}) {
  const prefersReducedMotion = useReducedMotion();
  const enterMotion = createEnterMotion(prefersReducedMotion, { delay });
  const interactiveMotion = hoverable ? createInteractiveMotion(prefersReducedMotion, { hoverScale: 1.01 }) : {};

  const Component = motion[as] || motion.section;

  return (
    <Component
      className={cn(
        "rounded-3xl border border-slate-200/80 bg-white shadow-soft dark:border-slate-800/80 dark:bg-slate-950",
        hoverable &&
          "transition-shadow duration-200 hover:shadow-panel dark:hover:shadow-[0_20px_36px_-22px_rgba(13,148,96,0.35)]",
        className
      )}
      {...enterMotion}
      {...interactiveMotion}
      {...rest}
    >
      {children}
    </Component>
  );
}
