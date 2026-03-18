import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useEffect } from "react";
import { createModalMotion } from "./motionSystem";

export default function Modal({
  open,
  onClose,
  ariaLabel,
  children,
  maxWidthClassName = "max-w-3xl",
  contentClassName = ""
}) {
  const prefersReducedMotion = useReducedMotion();
  const modalMotion = createModalMotion(prefersReducedMotion);

  useEffect(() => {
    if (!open || typeof window === "undefined") {
      return undefined;
    }

    const { body } = document;
    const previousOverflow = body.style.overflow;
    body.style.overflow = "hidden";

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose?.();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose, open]);

  return (
    <AnimatePresence>
      {open ? (
        <div className="fixed inset-0 z-[80] flex items-center justify-center p-4 sm:p-6">
          <motion.button
            type="button"
            aria-label="Close modal"
            className="absolute inset-0 bg-slate-900/55 backdrop-blur-[2px]"
            onClick={onClose}
            {...modalMotion.backdrop}
          />
          <motion.section
            role="dialog"
            aria-modal="true"
            aria-label={ariaLabel}
            className={`relative z-10 flex max-h-[88vh] w-full ${maxWidthClassName} flex-col overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-panel dark:border-slate-800 dark:bg-slate-950 ${contentClassName}`.trim()}
            {...modalMotion.panel}
          >
            {children}
          </motion.section>
        </div>
      ) : null}
    </AnimatePresence>
  );
}
