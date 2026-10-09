//! Whether JavaScript's `new RegExp(pattern)` accepts a pattern, with no flags.
//!
//! Upstream compiles an interior `{"$regex": ...}` atom with `new RegExp` (`MongoTransform.js:580-581`),
//! so a pattern JavaScript refuses is a `SyntaxError` and a bare 500, raised while the query is
//! built. parse-rust hands the pattern to MongoDB without compiling it, so it has to ask the same
//! question itself. This is a syntax check only, following ECMAScript's grammar without the `u` flag
//! and with Annex B's web-compatibility rules, which are what make `]`, `{` and `}` literals.
//!
//! The cases it answers were measured against Node; the tests below hold them.

use std::collections::HashMap;

/// V8's limit on capturing groups in one pattern, measured: 32,767 compile, 32,768 do not.
const MAX_CAPTURES: usize = 32_767;

/// Does `new RegExp(pattern)` succeed?
///
/// **Iterative and linear, because the pattern is a client's.** Open groups live on an explicit
/// stack rather than the call stack, so nesting depth cannot overflow it: V8 itself accepts tens
/// of thousands of levels. Every scan is done once, so a request carrying a pattern near the body
/// limit costs time proportional to its length. An earlier recursive version aborted the process
/// on a deeply nested pattern, and a name lookup per group made long patterns quadratic.
pub fn is_valid(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    // The position of the next `>` at or after each index, so a group name or a `\k<name>` is
    // found in constant time however many of them there are.
    let mut next_gt = vec![usize::MAX; chars.len() + 1];
    for i in (0..chars.len()).rev() {
        next_gt[i] = if chars[i] == '>' { i } else { next_gt[i + 1] };
    }
    let mut p = Parser {
        s: &chars,
        next_gt: &next_gt,
        i: 0,
        names: HashMap::new(),
        refs: Vec::new(),
        open: vec![Frame {
            start: None,
            alternative: 0,
        }],
        captures: 0,
    };
    if p.run().is_none() {
        return false;
    }
    // `\k<name>` must name a group somewhere in the pattern once any group is named; with none,
    // `\k` is an identity escape.
    if !p.names.is_empty() {
        return p.refs.iter().all(|r| match r {
            Some((start, end)) => {
                let name: String = chars[*start..*end].iter().collect();
                p.names.contains_key(&name)
            }
            None => false,
        });
    }
    true
}

struct Parser<'a> {
    s: &'a [char],
    next_gt: &'a [usize],
    i: usize,
    /// Each group name, with the position of the last group that took it. One position per name,
    /// never a copy of the nesting: storing each group's full path made memory grow with depth
    /// times groups, gigabytes from a pattern of a few hundred kilobytes.
    names: HashMap<String, usize>,
    /// Every `\k`: the span of the name it was followed by, if it was followed by one.
    refs: Vec<Option<(usize, usize)>>,
    /// The pattern itself, then each open group, outermost first.
    open: Vec<Frame>,
    captures: usize,
}

/// A disjunction being parsed: the pattern's own, or an open group's.
struct Frame {
    /// Where the group opened; `None` for the pattern itself, which contains everything.
    start: Option<usize>,
    /// Where its current alternative began. Increases with depth along the stack, because an inner
    /// group opens after its enclosing alternative began, and that alternative cannot change while
    /// the inner one is open.
    alternative: usize,
}

/// What may follow a group once it closes, kept with the group while it is open.
struct Open {
    quantifiable: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.s.get(self.i + offset).copied()
    }

    fn next_gt_from(&self, from: usize) -> Option<usize> {
        self.next_gt.get(from).copied().filter(|&j| j != usize::MAX)
    }

    /// The whole pattern: terms, `|` and groups, with open groups on `open`.
    fn run(&mut self) -> Option<()> {
        let mut open: Vec<Open> = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                '|' => {
                    let top = self.open.last_mut()?;
                    top.alternative = self.i;
                    self.i += 1;
                }
                ')' => {
                    // An unmatched `)`.
                    let group = open.pop()?;
                    self.open.pop();
                    self.i += 1;
                    if group.quantifiable {
                        self.quantifier()?;
                    }
                }
                '(' => {
                    let at = self.i;
                    let quantifiable = self.group_open()?;
                    open.push(Open { quantifiable });
                    self.open.push(Frame {
                        start: Some(at),
                        alternative: at,
                    });
                }
                _ => {
                    if self.term()? {
                        self.quantifier()?;
                    }
                }
            }
        }
        // An unterminated group.
        open.is_empty().then_some(())
    }

    /// One term other than a group, `|` or `)`. Returns whether a quantifier may follow it.
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
            // The name's span is recorded but **not skipped**. With no named group in the pattern,
            // `\k` is an identity escape and what follows is ordinary pattern, so `\k<[>` is an
            // unterminated class and `\k<(?:>)` a valid group; skipping to the `>` hid both. With
            // one, the name must be a group's, which is checked at the end, and an identifier's
            // characters parse as literals either way.
            'k' => {
                let name = if self.peek() == Some('<') {
                    let start = self.i + 1;
                    self.next_gt_from(start).map(|end| (start, end))
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

    /// A group's opening, up to its body. Returns whether a quantifier may follow the group.
    fn group_open(&mut self) -> Option<bool> {
        self.i += 1;
        if self.peek() != Some('?') {
            return self.capture();
        }
        self.i += 1;
        match (self.peek(), self.at(1)) {
            (Some(':'), _) => {
                self.i += 1;
                Some(true)
            }
            // Annex B lets a lookahead take a quantifier.
            (Some('=' | '!'), _) => {
                self.i += 1;
                Some(true)
            }
            (Some('<'), Some('=' | '!')) => {
                self.i += 2;
                Some(false)
            }
            (Some('<'), _) => {
                // The group's own `(`, two characters back.
                let at = self.i - 2;
                self.i += 1;
                let start = self.i;
                let end = self.next_gt_from(start)?;
                let name: String = self.s[start..end].iter().collect();
                if !is_identifier(&name) {
                    return None;
                }
                if let Some(&previous) = self.names.get(&name) {
                    if !self.in_another_alternative(previous) {
                        return None;
                    }
                }
                self.names.insert(name, at);
                self.i = end + 1;
                self.capture()
            }
            _ => {
                self.modifiers()?;
                Some(true)
            }
        }
    }

    /// Count a capturing group against V8's limit.
    fn capture(&mut self) -> Option<bool> {
        self.captures += 1;
        (self.captures <= MAX_CAPTURES).then_some(true)
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
    ///
    /// Checking the newest group against only the previous group of its name is enough: were it
    /// in the same alternative as an earlier one, the groups between would have collided first.
    /// The previous group, at `previous`, is in another alternative exactly when some open group
    /// that contains it has begun a later alternative since. The open groups that contain it are a
    /// prefix of the stack, and alternative starts increase along it, so the deepest of them
    /// decides, found by binary search.
    fn in_another_alternative(&self, previous: usize) -> bool {
        let containing = self
            .open
            .partition_point(|f| f.start.is_none_or(|start| start < previous));
        containing > 0 && self.open[containing - 1].alternative > previous
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
            ("\\k<[>", false),
            ("\\k<a(>", false),
            ("\\k<(?:>)", true),
            ("\\k<)>", false),
            ("(?<a>x)\\k<[>", false),
            ("\\k<", true),
            ("\\k<a", true),
        ];
        for (pattern, valid) in cases {
            assert_eq!(is_valid(pattern), *valid, "{pattern:?}");
        }
    }

    /// Depth costs no stack: V8 accepts this, and the recursive version aborted the process.
    #[test]
    fn deep_nesting_is_checked_without_recursion() {
        for n in [10_000, 200_000] {
            let p = format!("{}{}", "(?:".repeat(n), ")".repeat(n));
            assert!(is_valid(&p), "{n}");
            let unclosed = "(?:".repeat(n);
            assert!(!is_valid(&unclosed), "{n}");
        }
        // V8's capture limit, measured: 32,767 compile and 32,768 do not.
        assert!(is_valid(&"(a)".repeat(32_767)));
        assert!(!is_valid(&"(a)".repeat(32_768)));
        assert!(is_valid(&format!(
            "{}{}",
            "(".repeat(32_767),
            ")".repeat(32_767)
        )));
    }

    /// The reported case, on the stack size a tokio worker gets: 20,000 groups around `a`, which
    /// Node accepts, aborted the recursive version.
    #[test]
    fn twenty_thousand_groups_fit_a_two_megabyte_stack() {
        let checked = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let n = 20_000;
                is_valid(&format!("{}a{}", "(".repeat(n), ")".repeat(n)))
            })
            .expect("spawn")
            .join()
            .expect("no overflow");
        assert!(checked);
    }

    /// Many named groups deep inside nesting, and many groups sharing one name across alternatives:
    /// the shapes that stored a path per group and compared each group with every earlier one.
    #[test]
    fn named_groups_deep_in_nesting_cost_neither_memory_nor_time() {
        let distinct: String = (0..30_000).map(|i| format!("(?<a{i}>)")).collect();
        let shared: String = (0..30_000)
            .map(|i| {
                if i == 0 {
                    "(?<a>)".to_string()
                } else {
                    "|(?<a>)".to_string()
                }
            })
            .collect();
        // The reviewed shapes: deep nesting around tens of thousands of named groups, and
        // same-name siblings across alternatives, shallow and deep.
        let cases = [
            (100_000, distinct.clone()),
            (600_000, distinct),
            (3_000, shared.clone()),
            (100_000, shared),
        ];
        for (depth, body) in cases {
            let p = format!("{}{body}{}", "(?:".repeat(depth), ")".repeat(depth));
            let started = std::time::Instant::now();
            assert!(is_valid(&p));
            let took = started.elapsed();
            assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
        }
        // The rule itself, at depth: siblings in one alternative collide, alternatives do not.
        let wrap = |inner: &str| format!("{}{inner}{}", "(?:".repeat(1000), ")".repeat(1000));
        assert!(!is_valid(&wrap("(?<a>)(?<a>)")));
        assert!(is_valid(&wrap("(?<a>)|(?<a>)")));
        assert!(!is_valid(&wrap("(?:(?<a>)|(?<a>))(?<a>)")));
        assert!(is_valid(&wrap("(?<a>)|(?:(?<a>)|(?<a>))")));
    }

    /// Long patterns of the shapes that were quadratic answer in time linear in their length.
    #[test]
    fn long_patterns_are_linear() {
        let cases = [
            "\\k<".repeat(160_000),
            (0..60_000)
                .map(|i| format!("(?<a{i}>)"))
                .collect::<String>(),
            format!("(?<a>x){}", "\\k<a>".repeat(100_000)),
            "(?<a".repeat(200_000),
        ];
        for p in &cases {
            let started = std::time::Instant::now();
            let _ = is_valid(p);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(2),
                "{} bytes took {took:?}",
                p.len()
            );
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
