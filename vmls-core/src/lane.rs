//! The send-lane decision for a composer, as a pure table.
//!
//! A sheltered (VMLS/1) conversation never produces NIP-17. The only way to
//! the public lane from it is the person's explicit choice, and that choice
//! starts a separate public conversation into which nothing is copied: no
//! GroupId, binding, roster, draft or read state. The new composer opens
//! empty; the person's own unsent text reaches it only by a further explicit
//! action of theirs. A conversation that is already public never becomes
//! sheltered here; returning to a sheltered route is a new, visible
//! decision. The wording keys name rows of the client's wording table.

/// What the composer is attached to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Conversation {
    /// An existing VMLS/1 group.
    Sheltered,
    /// An existing NIP-17 conversation.
    Public,
    /// A first message to a person, before any conversation exists.
    New,
}

/// The local group state, read only for a sheltered conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroupState {
    Active,
    /// Sends stop until repair (forks, failed transitions, gap timeouts).
    NeedsRecovery,
}

/// The person's explicit choice, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Choice {
    None,
    /// "Start a separate public message", pressed by the person.
    StartPublic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LaneInput {
    pub conversation: Conversation,
    pub group_state: GroupState,
    /// A valid `capability/1` from this person is held.
    pub peer_capability: bool,
    /// A permitted sheltered carrier (v1: the box route) is available now.
    pub sheltered_route: bool,
    pub choice: Choice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    SendSheltered,
    CreateShelteredConversation,
    /// Keep the draft on this device. Nothing leaves it.
    Hold,
    /// Nothing is sent; the composer offers a separate public message.
    OfferPublic,
    /// Open a new, empty NIP-17 composer. Nothing is copied from the
    /// sheltered conversation; the person's own draft text only by their
    /// further explicit action.
    StartPublicConversation,
    SendNip17,
}

/// The lane chip for what happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Indicator {
    Sheltered,
    Public,
    NotSent,
}

/// A row of the client's wording table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Wording {
    LaneSheltered,
    LanePublic,
    ShelteredUnavailable,
    StartSeparatePublic,
    NeedsRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decision {
    pub action: Action,
    pub indicator: Indicator,
    pub wording: Wording,
    /// Show the "start a separate public message" choice.
    pub offer_public: bool,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendSheltered => "send-sheltered",
            Self::CreateShelteredConversation => "create-sheltered-conversation",
            Self::Hold => "hold",
            Self::OfferPublic => "offer-public",
            Self::StartPublicConversation => "start-public-conversation",
            Self::SendNip17 => "send-nip17",
        }
    }
}

impl Indicator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sheltered => "sheltered",
            Self::Public => "public",
            Self::NotSent => "not-sent",
        }
    }
}

impl Wording {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LaneSheltered => "sheltered",
            Self::LanePublic => "public",
            Self::ShelteredUnavailable => "sheltered-unavailable",
            Self::StartSeparatePublic => "start-separate-public",
            Self::NeedsRecovery => "needs-recovery",
        }
    }
}

const fn decision(
    action: Action,
    indicator: Indicator,
    wording: Wording,
    offer_public: bool,
) -> Decision {
    Decision {
        action,
        indicator,
        wording,
        offer_public,
    }
}

const SEND_SHELTERED: Decision = decision(
    Action::SendSheltered,
    Indicator::Sheltered,
    Wording::LaneSheltered,
    false,
);
const CREATE_SHELTERED: Decision = decision(
    Action::CreateShelteredConversation,
    Indicator::Sheltered,
    Wording::LaneSheltered,
    false,
);
const HOLD_UNAVAILABLE: Decision = decision(
    Action::Hold,
    Indicator::NotSent,
    Wording::ShelteredUnavailable,
    true,
);
const HOLD_RECOVERY: Decision = decision(
    Action::Hold,
    Indicator::NotSent,
    Wording::NeedsRecovery,
    true,
);
const OFFER_PUBLIC: Decision = decision(
    Action::OfferPublic,
    Indicator::NotSent,
    Wording::StartSeparatePublic,
    true,
);
const START_PUBLIC: Decision = decision(
    Action::StartPublicConversation,
    Indicator::Public,
    Wording::LanePublic,
    false,
);
const SEND_NIP17: Decision = decision(
    Action::SendNip17,
    Indicator::Public,
    Wording::LanePublic,
    false,
);

/// The decision for one composer state.
pub const fn decide(input: LaneInput) -> Decision {
    match input.conversation {
        Conversation::Public => SEND_NIP17,
        Conversation::Sheltered => match (input.choice, input.group_state, input.sheltered_route) {
            (Choice::StartPublic, _, _) => START_PUBLIC,
            (Choice::None, GroupState::NeedsRecovery, _) => HOLD_RECOVERY,
            (Choice::None, GroupState::Active, true) => SEND_SHELTERED,
            (Choice::None, GroupState::Active, false) => HOLD_UNAVAILABLE,
        },
        Conversation::New => match (input.choice, input.peer_capability, input.sheltered_route) {
            (Choice::StartPublic, _, _) => START_PUBLIC,
            (Choice::None, false, _) => OFFER_PUBLIC,
            (Choice::None, true, true) => CREATE_SHELTERED,
            (Choice::None, true, false) => HOLD_UNAVAILABLE,
        },
    }
}

/// Every input, in the order the published vector lists them.
pub fn all_inputs() -> Vec<LaneInput> {
    let mut out = Vec::with_capacity(48);
    for conversation in [
        Conversation::Sheltered,
        Conversation::Public,
        Conversation::New,
    ] {
        for group_state in [GroupState::Active, GroupState::NeedsRecovery] {
            for peer_capability in [true, false] {
                for sheltered_route in [true, false] {
                    for choice in [Choice::None, Choice::StartPublic] {
                        out.push(LaneInput {
                            conversation,
                            group_state,
                            peer_capability,
                            sheltered_route,
                            choice,
                        });
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants_hold_for_every_input() {
        let inputs = all_inputs();
        assert_eq!(inputs.len(), 48);
        for input in inputs {
            let out = decide(input);
            let public = matches!(
                out.action,
                Action::SendNip17 | Action::StartPublicConversation
            );
            let sheltered = matches!(
                out.action,
                Action::SendSheltered | Action::CreateShelteredConversation
            );
            // A sheltered conversation never produces NIP-17.
            if input.conversation == Conversation::Sheltered {
                assert_ne!(out.action, Action::SendNip17, "{input:?}");
            }
            // Nothing reaches the public lane from a sheltered or new
            // composer without the explicit choice, and that choice always
            // starts a separate conversation.
            if public && input.conversation != Conversation::Public {
                assert_eq!(input.choice, Choice::StartPublic, "{input:?}");
                assert_eq!(out.action, Action::StartPublicConversation, "{input:?}");
            }
            // A public conversation never becomes sheltered on its own, and
            // nobody without a capability record is sent anything sheltered.
            if sheltered {
                assert_ne!(input.conversation, Conversation::Public, "{input:?}");
                assert_eq!(input.choice, Choice::None, "{input:?}");
                assert!(input.sheltered_route, "{input:?}");
            }
            if input.conversation == Conversation::New && !input.peer_capability {
                assert!(!sheltered, "{input:?}");
            }
            // A group that needs recovery sends nothing sheltered.
            if input.conversation == Conversation::Sheltered
                && input.group_state == GroupState::NeedsRecovery
            {
                assert!(!sheltered, "{input:?}");
            }
            // The chip always matches the action.
            let expected = if sheltered {
                Indicator::Sheltered
            } else if public {
                Indicator::Public
            } else {
                Indicator::NotSent
            };
            assert_eq!(out.indicator, expected, "{input:?}");
            assert_eq!(
                out.offer_public,
                out.indicator == Indicator::NotSent,
                "{input:?}"
            );
        }
    }
}
