import { SPRING_EASE } from "../appUtils";

const DEFAULT_DURATION = 0.28;
const DEFAULT_OFFSET_Y = 10;
const DEFAULT_STAGGER = 0.045;

export function createEnterMotion(reducedMotion, options = {}) {
  const {
    delay = 0,
    duration = DEFAULT_DURATION,
    y = DEFAULT_OFFSET_Y,
    opacity = 1
  } = options;

  if (reducedMotion) {
    return {
      initial: false,
      animate: {}
    };
  }

  return {
    initial: { opacity: 0, y },
    animate: { opacity, y: 0 },
    transition: {
      duration,
      ease: SPRING_EASE,
      delay
    }
  };
}

export function createPageTransitionMotion(reducedMotion, options = {}) {
  if (reducedMotion) {
    return {
      initial: false,
      animate: { opacity: 1 },
      exit: { opacity: 1 }
    };
  }

  const { duration = 0.24, y = 8 } = options;

  return {
    initial: { opacity: 0, y },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -6 },
    transition: {
      duration,
      ease: SPRING_EASE
    }
  };
}

export function createStaggerContainerVariants(reducedMotion, options = {}) {
  if (reducedMotion) {
    return {
      hidden: {},
      show: {}
    };
  }

  const {
    staggerChildren = DEFAULT_STAGGER,
    delayChildren = 0.02
  } = options;

  return {
    hidden: { opacity: 1 },
    show: {
      opacity: 1,
      transition: {
        delayChildren,
        staggerChildren
      }
    }
  };
}

export function createStaggerItemVariants(reducedMotion, options = {}) {
  if (reducedMotion) {
    return {
      hidden: {},
      show: {}
    };
  }

  const { y = 8, duration = 0.22 } = options;

  return {
    hidden: { opacity: 0, y },
    show: {
      opacity: 1,
      y: 0,
      transition: {
        duration,
        ease: SPRING_EASE
      }
    }
  };
}

export function createInteractiveMotion(reducedMotion, options = {}) {
  if (reducedMotion) {
    return {};
  }

  const {
    hoverScale = 1.02,
    tapScale = 0.985
  } = options;

  return {
    whileHover: { scale: hoverScale },
    whileTap: { scale: tapScale }
  };
}

export function createModalMotion(reducedMotion) {
  if (reducedMotion) {
    return {
      backdrop: {
        initial: { opacity: 0 },
        animate: { opacity: 1 },
        exit: { opacity: 0 }
      },
      panel: {
        initial: { opacity: 0 },
        animate: { opacity: 1 },
        exit: { opacity: 0 }
      }
    };
  }

  return {
    backdrop: {
      initial: { opacity: 0 },
      animate: { opacity: 1 },
      exit: { opacity: 0 },
      transition: { duration: 0.2, ease: "easeOut" }
    },
    panel: {
      initial: { opacity: 0, scale: 0.95, y: 10 },
      animate: { opacity: 1, scale: 1, y: 0 },
      exit: { opacity: 0, scale: 0.97, y: 8 },
      transition: { duration: 0.24, ease: SPRING_EASE }
    }
  };
}
