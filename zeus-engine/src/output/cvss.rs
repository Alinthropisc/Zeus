//! CVSS v3 score builder — used by production code and fuzz targets.

/// CVSS v3 metric enumerations and builder.
///
/// `from_bytes` maps raw byte slices to enum variants via modulo, enabling
/// libfuzzer to drive the builder with arbitrary input.
#[derive(Debug, Clone)]
pub struct CvssV3Builder {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
}

#[derive(Debug, Clone, Copy)]
pub enum AttackVector { Network, Adjacent, Local, Physical }
#[derive(Debug, Clone, Copy)]
pub enum AttackComplexity { Low, High }
#[derive(Debug, Clone, Copy)]
pub enum PrivilegesRequired { None, Low, High }
#[derive(Debug, Clone, Copy)]
pub enum UserInteraction { None, Required }
#[derive(Debug, Clone, Copy)]
pub enum Scope { Unchanged, Changed }
#[derive(Debug, Clone, Copy)]
pub enum Impact { None, Low, High }

impl CvssV3Builder {
    /// Construct from at least 8 bytes; returns `None` if `data.len() < 8`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let av = match data[0] % 4 {
            0 => AttackVector::Network,
            1 => AttackVector::Adjacent,
            2 => AttackVector::Local,
            _ => AttackVector::Physical,
        };
        let ac = if data[1] % 2 == 0 { AttackComplexity::Low } else { AttackComplexity::High };
        let pr = match data[2] % 3 {
            0 => PrivilegesRequired::None,
            1 => PrivilegesRequired::Low,
            _ => PrivilegesRequired::High,
        };
        let ui = if data[3] % 2 == 0 { UserInteraction::None } else { UserInteraction::Required };
        let sc = if data[4] % 2 == 0 { Scope::Unchanged } else { Scope::Changed };
        let conf = match data[5] % 3 { 0 => Impact::None, 1 => Impact::Low, _ => Impact::High };
        let integ = match data[6] % 3 { 0 => Impact::None, 1 => Impact::Low, _ => Impact::High };
        let avail = match data[7] % 3 { 0 => Impact::None, 1 => Impact::Low, _ => Impact::High };

        Some(Self {
            attack_vector: av,
            attack_complexity: ac,
            privileges_required: pr,
            user_interaction: ui,
            scope: sc,
            confidentiality: conf,
            integrity: integ,
            availability: avail,
        })
    }

    /// Compute the CVSS v3 base score (0.0–10.0).
    pub fn score(&self) -> f32 {
        // ISC / ESC sub-scores using CVSS v3.1 formula (simplified).
        let c = impact_score(self.confidentiality);
        let i = impact_score(self.integrity);
        let a = impact_score(self.availability);
        let isc = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);

        let iss = match self.scope {
            Scope::Unchanged => 6.42 * isc,
            Scope::Changed => 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02_f32).powi(15),
        };

        if iss <= 0.0 {
            return 0.0;
        }

        let exploitability = 8.22
            * av_score(self.attack_vector)
            * ac_score(self.attack_complexity)
            * pr_score(self.privileges_required, self.scope)
            * ui_score(self.user_interaction);

        let base = match self.scope {
            Scope::Unchanged => f32::min(iss + exploitability, 10.0),
            Scope::Changed => f32::min(1.08 * (iss + exploitability), 10.0),
        };

        // Round up to 1 decimal place.
        (base * 10.0).ceil() / 10.0
    }
}

fn impact_score(i: Impact) -> f32 {
    match i { Impact::None => 0.0, Impact::Low => 0.22, Impact::High => 0.56 }
}
fn av_score(v: AttackVector) -> f32 {
    match v { AttackVector::Network => 0.85, AttackVector::Adjacent => 0.62,
              AttackVector::Local => 0.55, AttackVector::Physical => 0.20 }
}
fn ac_score(c: AttackComplexity) -> f32 {
    match c { AttackComplexity::Low => 0.77, AttackComplexity::High => 0.44 }
}
fn pr_score(p: PrivilegesRequired, s: Scope) -> f32 {
    match (p, s) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, Scope::Changed) => 0.68,
        (PrivilegesRequired::Low, _) => 0.62,
        (PrivilegesRequired::High, Scope::Changed) => 0.50,
        (PrivilegesRequired::High, _) => 0.27,
    }
}
fn ui_score(u: UserInteraction) -> f32 {
    match u { UserInteraction::None => 0.85, UserInteraction::Required => 0.62 }
}
