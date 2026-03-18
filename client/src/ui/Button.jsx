import { motion, useReducedMotion } from "framer-motion";
import { cn } from "../dashboard/dashboardUtils";
import { createInteractiveMotion } from "./motionSystem";

const BASE_CLASS =
  "inline-flex items-center justify-center gap-2 rounded-xl border text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-viro-300 disabled:cursor-not-allowed disabled:opacity-45 dark:focus-visible:ring-viro-700";

const VARIANT_CLASS = {
  primary:
    "border-viro-600 bg-viro-600 text-white shadow-soft hover:border-viro-700 hover:bg-viro-700 dark:border-viro-500 dark:bg-viro-500 dark:hover:border-viro-400 dark:hover:bg-viro-400",
  secondary:
    "border-slate-200 bg-white text-slate-700 shadow-soft hover:border-viro-300 hover:bg-viro-50 hover:text-viro-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:border-viro-700 dark:hover:bg-viro-900/40 dark:hover:text-emerald-200",
  ghost:
    "border-transparent bg-transparent text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white",
  danger:
    "border-rose-600 bg-rose-600 text-white shadow-soft hover:border-rose-700 hover:bg-rose-700 dark:border-rose-500 dark:bg-rose-500 dark:hover:border-rose-400 dark:hover:bg-rose-400"
};

const SIZE_CLASS = {
  sm: "h-9 px-3",
  md: "h-10 px-4",
  lg: "h-11 px-5"
};

export default function Button({
  children,
  className = "",
  variant = "primary",
  size = "md",
  type = "button",
  disabled = false,
  ...rest
}) {
  const prefersReducedMotion = useReducedMotion();
  const interactiveMotion = createInteractiveMotion(prefersReducedMotion, {
    hoverScale: 1.01,
    tapScale: 0.985
  });

  return (
    <motion.button
      type={type}
      disabled={disabled}
      className={cn(
        BASE_CLASS,
        VARIANT_CLASS[variant] || VARIANT_CLASS.primary,
        SIZE_CLASS[size] || SIZE_CLASS.md,
        className
      )}
      {...interactiveMotion}
      {...rest}
    >
      {children}
    </motion.button>
  );
}
