import { create } from 'zustand';

interface UiState {
  sidebarCollapsed: boolean;
  unavailableDialogOpen: boolean;
  toggleSidebar: () => void;
  showUnavailableDialog: () => void;
  hideUnavailableDialog: () => void;
}

export const useUiStore = create<UiState>((set) => ({
  sidebarCollapsed: false,
  unavailableDialogOpen: false,
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  showUnavailableDialog: () => set({ unavailableDialogOpen: true }),
  hideUnavailableDialog: () => set({ unavailableDialogOpen: false }),
}));
