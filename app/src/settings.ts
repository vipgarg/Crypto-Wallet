// App-wide settings shared with every page (kept in the encrypted store).
import { createContext, useContext } from "react";

/** True when Bitcoin is shown and checked; false when paused. */
export const BitcoinContext = createContext(true);

export function useBitcoin(): boolean {
  return useContext(BitcoinContext);
}
