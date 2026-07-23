export const portalKnowledge = {
  identity: {
    name: process.env.REALM_NAME || "AzerothCore",
    description: "A private AzerothCore realm managed through Acore Portal."
  },
  modules: ["mod-acore-portal-tools", "mod-playerbots", "mod-ah-bot"],
  customCommands: [
    { command: ".portaltools repairbot <character> [durationMinutes] [creatureEntry]", purpose: "Summon a temporary repair vendor near an online character." },
    { command: ".portaltools summonto <character> <destinationCharacter>", purpose: "Move one online character to another online character." },
    { command: ".portaltools queueav <character>", purpose: "Queue an online raid for Alterac Valley." }
  ],
  adminActionPolicy: "Use curated portal actions. Avoid direct database changes unless the administrator understands the impact."
};

export function compactPortalKnowledge() {
  return portalKnowledge;
}
