//! Whether JavaScript's `new RegExp(pattern)` accepts a pattern, with no flags.
//!
//! Upstream compiles an interior `{"$regex": ...}` atom with `new RegExp` (`MongoTransform.js:580-581`),
//! so a pattern JavaScript refuses is a `SyntaxError` and a bare 500, raised while the query is
//! built. parse-rust hands the pattern to MongoDB without compiling it, so it has to ask the same
//! question itself. This is a syntax check only, following ECMAScript's grammar without the `u` flag
//! and with Annex B's web-compatibility rules, which are what make `]`, `{` and `}` literals.
//!
//! The cases it answers were measured against Node; the tests below hold them.

/// Does `new RegExp(pattern)` succeed?
pub fn is_valid(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut p = Parser {
        s: &chars,
        i: 0,
        names: Vec::new(),
        refs: Vec::new(),
        path: Vec::new(),
        next_disjunction: 0,
    };
    if p.disjunction().is_none() || p.i != chars.len() {
        return false;
    }
    // `\k<name>` must name a group somewhere in the pattern once any group is named; with none,
    // `\k` is an identity escape.
    if !p.names.is_empty() {
        return p.refs.iter().all(|r| match r {
            Some(name) => p.names.iter().any(|(n, _)| n == name),
            None => false,
        });
    }
    true
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
    /// Every named group, with the alternatives it sits in, outermost first.
    names: Vec<(String, Vec<(usize, usize)>)>,
    /// Every `\k`: the name it was followed by, if it was followed by one.
    refs: Vec<Option<String>>,
    /// The disjunction and alternative currently being parsed, outermost first.
    path: Vec<(usize, usize)>,
    next_disjunction: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.s.get(self.i + offset).copied()
    }

    /// Alternatives separated by `|`, up to an unconsumed `)` or the end.
    fn disjunction(&mut self) -> Option<()> {
        let id = self.next_disjunction;
        self.next_disjunction += 1;
        let mut alternative = 0;
        loop {
            self.path.push((id, alternative));
            let ok = self.alternative();
            self.path.pop();
            ok?;
            if self.peek() == Some('|') {
                self.i += 1;
                alternative += 1;
            } else {
                return Some(());
            }
        }
    }

    fn alternative(&mut self) -> Option<()> {
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                return Some(());
            }
            let quantifiable = self.term()?;
            if quantifiable {
                self.quantifier()?;
            }
        }
        Some(())
    }

    /// One term. Returns whether a quantifier may follow it.
    fn term(&mut self) -> Option<bool> {
        let c = self.peek()?;
        match c {
            '^' | '$' => {
                self.i += 1;
                Some(false)
            }
            // A quantifier where an atom belongs: "Nothing to repeat".
            '*' | '+' | '?' => None,
            '{' if self.braced_quantifier_len().is_some() => None,
            '\\' => self.escape(),
            '(' => self.group(),
            '[' => {
                self.class()?;
                Some(true)
            }
            _ => {
                self.i += 1;
                Some(true)
            }
        }
    }

    fn quantifier(&mut self) -> Option<()> {
        match self.peek() {
            Some('*' | '+' | '?') => self.i += 1,
            Some('{') => match self.braced_quantifier_len() {
                Some(len) => {
                    if !self.braced_in_order(len) {
                        return None;
                    }
                    self.i += len;
                }
                None => return Some(()),
            },
            _ => return Some(()),
        }
        // Lazy.
        if self.peek() == Some('?') {
            self.i += 1;
        }
        Some(())
    }

    /// The length of `{n}`, `{n,}` or `{n,m}` starting here, if one does.
    fn braced_quantifier_len(&self) -> Option<usize> {
        let mut j = 1;
        let digits = |j: &mut usize| {
            let start = *j;
            while self.at(*j).is_some_and(|c| c.is_ascii_digit()) {
                *j += 1;
            }
            *j > start
        };
        if self.at(0) != Some('{') || !digits(&mut j) {
            return None;
        }
        if self.at(j) == Some(',') {
            j += 1;
            digits(&mut j);
        }
        (self.at(j) == Some('}')).then_some(j + 1)
    }

    /// `{n,m}` with `n` above `m` is "numbers out of order", however large either is.
    fn braced_in_order(&self, len: usize) -> bool {
        let body: String = self.s[self.i + 1..self.i + len - 1].iter().collect();
        let Some((low, high)) = body.split_once(',') else {
            return true;
        };
        if high.is_empty() {
            return true;
        }
        let norm = |d: &str| d.trim_start_matches('0').to_string();
        let (low, high) = (norm(low), norm(high));
        (low.len(), low.as_str()) <= (high.len(), high.as_str())
    }

    /// An escape outside a class. Returns whether it is quantifiable.
    fn escape(&mut self) -> Option<bool> {
        self.i += 1;
        let c = self.peek()?;
        self.i += 1;
        match c {
            'b' | 'B' => Some(false),
            'k' => {
                let name = if self.peek() == Some('<') {
                    let start = self.i + 1;
                    let end = (start..self.s.len()).find(|&j| self.s[j] == '>');
                    end.map(|end| {
                        self.i = end + 1;
                        self.s[start..end].iter().collect::<String>()
                    })
                } else {
                    None
                };
                self.refs.push(name);
                Some(true)
            }
            // `\c` without a letter is a literal backslash, and the `c` is read again as an atom.
            'c' if !self.peek().is_some_and(|l| l.is_ascii_alphabetic()) => {
                self.i -= 1;
                Some(true)
            }
            'c' => {
                self.i += 1;
                Some(true)
            }
            _ => Some(true),
        }
    }

    fn group(&mut self) -> Option<bool> {
        self.i += 1;
        let quantifiable;
        if self.peek() == Some('?') {
            self.i += 1;
            match (self.peek(), self.at(1)) {
                (Some(':'), _) => {
                    self.i += 1;
                    quantifiable = true;
                }
                // Annex B lets a lookahead take a quantifier.
                (Some('=' | '!'), _) => {
                    self.i += 1;
                    quantifiable = true;
                }
                (Some('<'), Some('=' | '!')) => {
                    self.i += 2;
                    quantifiable = false;
                }
                (Some('<'), _) => {
                    self.i += 1;
                    let start = self.i;
                    let end = (start..self.s.len()).find(|&j| self.s[j] == '>')?;
                    let name: String = self.s[start..end].iter().collect();
                    if !is_identifier(&name) || self.duplicates(&name) {
                        return None;
                    }
                    self.names.push((name, self.path.clone()));
                    self.i = end + 1;
                    quantifiable = true;
                }
                _ => {
                    self.modifiers()?;
                    quantifiable = true;
                }
            }
        } else {
            quantifiable = true;
        }
        self.disjunction()?;
        if self.peek() != Some(')') {
            return None;
        }
        self.i += 1;
        Some(quantifiable)
    }

    /// `(?ims-ims:`: each flag at most once across both sides, and not both sides empty.
    fn modifiers(&mut self) -> Option<()> {
        let mut seen = Vec::new();
        let mut any = false;
        let mut dash = false;
        loop {
            match self.peek()? {
                c @ ('i' | 'm' | 's') => {
                    if seen.contains(&c) {
                        return None;
                    }
                    seen.push(c);
                    any = true;
                }
                '-' if !dash => dash = true,
                ':' if any => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
            self.i += 1;
        }
    }

    /// Two groups of one name may coexist only in different alternatives of some disjunction.
    fn duplicates(&self, name: &str) -> bool {
        self.names.iter().any(|(n, path)| {
            n == name
                && !path
                    .iter()
                    .zip(self.path.iter())
                    .any(|((d1, a1), (d2, a2))| d1 == d2 && a1 != a2)
        })
    }

    fn class(&mut self) -> Option<()> {
        self.i += 1;
        if self.peek() == Some('^') {
            self.i += 1;
        }
        let mut previous: Option<Option<u32>> = None;
        let mut pending_range = false;
        loop {
            let c = self.peek()?;
            if c == ']' {
                self.i += 1;
                return Some(());
            }
            if c == '-' && previous.is_some() && !pending_range && self.at(1) != Some(']') {
                self.i += 1;
                pending_range = true;
                continue;
            }
            let atom = self.class_atom()?;
            if pending_range {
                if let (Some(Some(low)), Some(high)) = (previous, atom) {
                    if low > high {
                        return None;
                    }
                }
                pending_range = false;
                previous = None;
            } else {
                previous = Some(atom);
            }
        }
    }

    /// One class atom: its code point, or `None` for a class escape such as `\d`.
    fn class_atom(&mut self) -> Option<Option<u32>> {
        let c = self.peek()?;
        self.i += 1;
        if c != '\\' {
            return Some(Some(c as u32));
        }
        let e = self.peek()?;
        self.i += 1;
        let hex = |p: &mut Self, n: usize| -> Option<u32> {
            let digits: String = p.s.get(p.i..p.i + n)?.iter().collect();
            let v = u32::from_str_radix(&digits, 16).ok()?;
            if digits.chars().all(|d| d.is_ascii_hexdigit()) {
                p.i += n;
                Some(v)
            } else {
                None
            }
        };
        Some(match e {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' => None,
            'b' => Some(8),
            'n' => Some(10),
            't' => Some(9),
            'r' => Some(13),
            'v' => Some(11),
            'f' => Some(12),
            'x' => Some(hex(self, 2).unwrap_or('x' as u32)),
            'u' => Some(hex(self, 4).unwrap_or('u' as u32)),
            'c' => match self.peek() {
                Some(l) if l.is_ascii_alphanumeric() || l == '_' => {
                    self.i += 1;
                    Some(l as u32 % 32)
                }
                // A literal backslash; the `c` is read again.
                _ => {
                    self.i -= 1;
                    Some('\\' as u32)
                }
            },
            '0'..='7' => {
                let mut v = e.to_digit(8)?;
                for _ in 0..2 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) if v * 8 + d <= 0o377 => {
                            v = v * 8 + d;
                            self.i += 1;
                        }
                        _ => break,
                    }
                }
                Some(v)
            }
            other => Some(other as u32),
        })
    }
}

/// A JavaScript `IdentifierName`, approximately: a letter, `$` or `_`, then letters, digits, `$`
/// or `_`.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '$' || first == '_')
        && chars.all(|c| {
            c.is_alphanumeric() || c == '$' || c == '_' || c == '\u{200c}' || c == '\u{200d}'
        })
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    /// Each verdict measured with `new RegExp(p)` in Node 24.
    #[test]
    fn matches_node() {
        let cases: &[(&str, bool)] = &[
            ("[", false),
            ("]", true),
            ("a]", true),
            ("{", true),
            ("}", true),
            ("a{", true),
            ("a{1", true),
            ("a{1}", true),
            ("{1}", false),
            ("a{2,1}", false),
            ("a{1,2}", true),
            ("a{,2}", true),
            ("x{1,}", true),
            ("*", false),
            ("+", false),
            ("?", false),
            ("a**", false),
            ("a*?", true),
            ("a*??", false),
            ("a+*", false),
            ("(", false),
            (")", false),
            ("a)", false),
            ("(a", false),
            ("(?:a)", true),
            ("(?=a)", true),
            ("(?!a)", true),
            ("(?<=a)", true),
            ("(?<!a)", true),
            ("(?=a)*", true),
            ("(?<=a)*", false),
            ("(?<a>b)", true),
            ("(?<1a>b)", false),
            ("(?<a>b)(?<a>c)", false),
            ("(?<a>b)|(?<a>c)", true),
            ("(?x)", false),
            ("(?i:a)", true),
            ("(?-i:a)", true),
            ("(?i-s:a)", true),
            ("(?ii:a)", false),
            ("(?", false),
            ("(?<", false),
            ("\\", false),
            ("a\\", false),
            ("\\k", true),
            ("\\k<a>", true),
            ("(?<a>x)\\k<b>", false),
            ("(?<a>x)\\k<a>", true),
            ("\\1", true),
            ("(a)\\2", true),
            ("[z-a]", false),
            ("[a-z]", true),
            ("[\\d-a]", true),
            ("[a-\\d]", true),
            ("[\\x41-\\x40]", false),
            ("[\\u0041-\\u0040]", false),
            ("[\\n-\\t]", false),
            ("[--a]", true),
            ("[a-]", true),
            ("[-a]", true),
            ("[]", true),
            ("[^]", true),
            ("a|*", false),
            ("a|", true),
            ("|", true),
            ("^*", false),
            ("$*", false),
            ("\\b*", false),
            ("\\B+", false),
            ("a{1}{2}", false),
            ("a{1}?", true),
            ("a{1}??", false),
            ("^\\Qa\\E", true),
            ("^\\Qa[\\E", false),
            ("\\c", true),
            ("\\cA", true),
            ("\\x", true),
            ("\\u", true),
            ("\\u{41}", true),
            ("\\p{L}", true),
            ("\\0", true),
            ("\\08", true),
            ("[\\b]", true),
            ("a{99999999999}", true),
            ("a{1,99999999999}", true),
            ("(?<a>", false),
            ("x(?:", false),
            ("[\\]", false),
            ("[\\]]", true),
            ("a\u{0}b", true),
            ("((a)", false),
            ("(a))", false),
            (".*+", false),
            ("(?:)", true),
            ("()", true),
            ("(|)", true),
            ("a{0}", true),
            ("a{2,2}", true),
            ("a{3,2}?", false),
            ("[\\s-z]", true),
            ("[a-\\s]", true),
            ("[\\c]", true),
            ("\\ca-", true),
            ("[\\cZ-\\cA]", false),
            ("(?<$a>b)", true),
            ("(?<a_b>b)", true),
            ("(?<ab\u{1F600}>b)", false),
            ("\\k<a>(?<a>x)", true),
            ("(?<=a)+", false),
            ("(?!a)+", true),
            ("(?!a){2}", true),
        ];
        for (pattern, valid) in cases {
            assert_eq!(is_valid(pattern), *valid, "{pattern:?}");
        }
    }

    /// Random patterns over the metacharacters, judged by Node and by [`is_valid`].
    ///
    /// `#[ignore]`d because it shells out to node; `tools/test.sh` runs it.
    #[test]
    #[ignore = "requires node; run via tools/test.sh"]
    fn random_patterns_match_node() {
        const ALPHABET: &[&str] = &[
            "a", "b", "1", "2", "3", "(", ")", "[", "]", "{", "}", "*", "+", "?", "|", "^", "$",
            "\\", "-", ",", "<", ">", "=", "!", ":", "k", "c", "d", "x", "u", "0", "i", "s", "m",
            ".", "B", "p", "n", "_", "\u{0}", "A", "Z", "f", "7",
        ];
        let mut seed: u64 = 0x5eed;
        let mut next = |n: usize| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) as usize) % n
        };
        let patterns: Vec<String> = (0..20_000)
            .map(|_| {
                (0..1 + next(14))
                    .map(|_| ALPHABET[next(ALPHABET.len())])
                    .collect()
            })
            .collect();
        let input = serde_json::to_string(&patterns).expect("serialize");
        let script = "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{\
            console.log(JSON.stringify(JSON.parse(s).map(p=>{try{new RegExp(p);return true}catch{return false}})))})";
        let mut child = std::process::Command::new("node")
            .env_remove("NODE_OPTIONS")
            .args(["-e", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("node must be on PATH; this test is #[ignore]d by default");
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().expect("stdin");
            stdin.write_all(input.as_bytes()).expect("write");
        }
        let out = child.wait_with_output().expect("node ran");
        let verdicts: Vec<bool> = serde_json::from_slice(&out.stdout).expect("node verdicts");
        let wrong: Vec<(&String, bool)> = patterns
            .iter()
            .zip(verdicts)
            .filter(|(p, v)| is_valid(p) != *v)
            .collect();
        assert!(
            wrong.is_empty(),
            "{} disagreements, first: {:?}",
            wrong.len(),
            &wrong[..wrong.len().min(20)]
        );
    }
}
