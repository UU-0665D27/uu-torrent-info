use landlock::{
    ABI, Access, AccessFs, AccessNet, CreateRulesetError, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError,
};
pub fn appl_landlock(torrent: &String) -> Result<(), RulesetError> {
    let abi = ABI::V9;
    let access_all_fs = AccessFs::from_all(abi);
    let access_all_net = AccessNet::from_all(abi);

    let mut created = Ruleset::default()
        .handle_access(access_all_fs)?
        .handle_access(access_all_net)?
        .create()?;

    let fd = PathFd::new(torrent)
        .map_err(|_| RulesetError::CreateRuleset(CreateRulesetError::MissingHandledAccess))?;
    created = created.add_rule(PathBeneath::new(fd, access_all_fs))?;

    created.restrict_self()?;
    Ok(())
}
