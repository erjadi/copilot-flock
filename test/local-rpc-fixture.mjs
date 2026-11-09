export function localRpcFixture(api) {
  const prepare = (cfg, input) => {
    const { registryMembers = [], flockPolicy, maxSkewMs, enforceSignature, ...request } = input;
    const members = registryMembers.map((member, index) => ({
      ...member, active: true,
      peerId: member.peerId || `${member.githubUser === "erjadi" ? 1001 : 2002}:fixture-${index}`,
      githubUserId: member.githubUserId || (member.githubUser === "erjadi" ? 1001 : 2002),
      trustTier: member.trustTier || "owner", membershipExpiresAtMs: null,
    }));
    const claimed = input.auth?.fromMachine || input.fromMachine || input.params?.fromMachine || cfg.machineId;
    const peer = members.find((member) => member.machineId.toLowerCase() === String(claimed).toLowerCase());
    const user = peer?.githubUser || input.params?.fromGitHubUser || cfg.githubUser || null;
    const cross = Boolean(user && cfg.githubUser && user.toLowerCase() !== cfg.githubUser.toLowerCase());
    const policy = flockPolicy || (request.flockId ? api.loadLocalFlocksConfig(cfg).flocks[request.flockId] : null);
    if (request.flockId && !policy) throw new Error("Fixture selected an unknown receiver policy");
    const context = api.createLocalRpcContext(cfg, {
      members, policy, maxSkewMs: maxSkewMs || 300000,
      senderIdentity: {
        fromMachine: peer?.machineId || claimed, fromGitHubUser: user,
        fromScope: peer?.scope || input.params?.fromScope || cfg.scope || "work",
        senderVerified: false, isCrossUser: cross,
        trustLevel: cross ? "cross_user_informational_only" : "same_user_local",
      },
    });
    return { request, context };
  };
  return {
    handleRpcAction: (cfg, input) => {
      const { request, context } = prepare(cfg, input);
      return api.handleRpcAction(cfg, request, context);
    },
    resolveVerifiedSenderIdentity: (cfg, input) => {
      const { request, context } = prepare(cfg, input);
      return api.resolveVerifiedSenderIdentity(cfg, request, context);
    },
  };
}
