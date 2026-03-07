# GitHub Projects Scrum Setup Guide

**Project**: WolfGuard VPN Server (github.com/users/dantte-lp/projects/3)
**Created**: 2025-10-30
**Purpose**: Configure GitHub Projects v2 following Scrum best practices

---

## Overview

This guide provides step-by-step instructions to configure the WolfGuard GitHub Project board using Scrum methodology with proper fields, views, and automation.

## Part 1: Custom Fields Setup

Navigate to your project settings and create the following custom fields:

### 1. Sprint (Single Select)
**Purpose**: Track which sprint the issue belongs to

**Options**:
- `Sprint 0` - Project Setup (COMPLETED)
- `Sprint 1` - PoC & Critical Analysis (COMPLETED)
- `Sprint 2` - Development Tools & wolfSSL Integration (CURRENT)
- `Sprint 3` - Phase 1 Core Work
- `Sprint 4` - Phase 1 Completion
- `Sprint 5` - Phase 2 Core TLS Migration
- `Sprint 6` - Phase 2 Certificate & DTLS
- `Sprint 7` - Phase 2 Completion & Testing
- `Sprint 8` - Phase 3 Security Testing
- `Sprint 9-15` - Add as needed for remaining phases
- `Backlog` - Not yet assigned to sprint

**Default**: `Backlog`

### 2. Story Points (Number)
**Purpose**: Estimate effort using Fibonacci scale

**Range**: 1, 2, 3, 5, 8, 13, 21, 34, 55, 89

**Guidelines**:
- **1-2 SP**: Trivial (< 4 hours)
- **3-5 SP**: Small (4-12 hours)
- **8-13 SP**: Medium (1-2 days)
- **21-34 SP**: Large (3-5 days)
- **55+ SP**: Epic (needs breakdown)

**Default**: Leave empty until estimated

### 3. Priority (Single Select)
**Purpose**: Business priority following P0-P3 scale

**Options**:
- `P0 - Critical` 🔴 - Blocking issues, security vulnerabilities
- `P1 - High` 🟡 - Important features, significant bugs
- `P2 - Medium` 🟢 - Nice to have, minor improvements
- `P3 - Low` ⚪ - Future enhancements, deferred items

**Default**: `P2 - Medium`

### 4. Phase (Single Select)
**Purpose**: Track which project phase the issue belongs to

**Options**:
- `Phase 0` - Preparation & Critical Analysis (COMPLETED)
- `Phase 1` - TLS Backend Implementation (CURRENT)
- `Phase 2` - Core TLS Migration
- `Phase 3` - Testing & Validation
- `Phase 4` - Optimization & Bug Fixing
- `Phase 5` - Documentation & Release Prep
- `Phase 6` - Stable Release & Post-Release

**Default**: Leave empty

### 5. Type (Single Select)
**Purpose**: Categorize issue type

**Options**:
- `Feature` - New functionality
- `Bug` - Defect or issue
- `Security` - Security vulnerability or hardening
- `Documentation` - Docs updates
- `Infrastructure` - Build, CI/CD, tooling
- `Technical Debt` - Code cleanup, refactoring
- `Research` - Investigation, spikes

**Default**: `Feature`

### 6. Risk Level (Single Select)
**Purpose**: Track technical or business risk

**Options**:
- `Critical` 🔴 - High risk of project failure
- `High` 🟡 - Significant risk, needs mitigation
- `Medium` 🟢 - Moderate risk, monitor
- `Low` ⚪ - Minimal risk

**Default**: `Low`

### 7. Upstream Issue (Text)
**Purpose**: Reference upstream ocserv issue (if applicable)

**Format**: `#585`, `#323`, `#638`, etc.

**Example**: `#585` for TLS version enforcement issue

### 8. Related User Stories (Text)
**Purpose**: Link related user stories

**Format**: `US-031, US-032`

---

## Part 2: Views Configuration

Create the following views to support Scrum workflow:

### View 1: Sprint Board (Primary View)
**Type**: Board
**Group By**: Status

**Columns**:
1. **Backlog** - Not yet started, not in current sprint
2. **Sprint Backlog** - Planned for current sprint, not started
3. **In Progress** 🔄 - Actively being worked on
4. **In Review** 🔍 - PR submitted, awaiting review
5. **Testing** 🧪 - Being tested/validated
6. **Done** ✅ - Completed in this sprint
7. **Blocked** 🚫 - Cannot proceed (dependency, blocker)

**Filters**:
- `Sprint = "Sprint 2"` (or current sprint)
- Show all issues in current sprint

**Sort**: Priority (P0 first), then Story Points (descending)

**Card Fields**: Title, Assignees, Story Points, Priority, Phase

### View 2: Product Backlog
**Type**: Table
**Purpose**: All issues not in current sprint

**Columns**:
- Title
- Status
- Priority
- Story Points
- Phase
- Sprint
- Assignees

**Filters**:
- `Sprint = "Backlog"` OR `Status = "Backlog"`

**Sort**: Priority (P0 first), then Phase (ascending)

**Group By**: Phase

### View 3: Security Issues
**Type**: Table
**Purpose**: Track all security-related issues

**Filters**:
- `Type = "Security"` OR `Priority = "P0 - Critical"`

**Sort**: Priority, then Sprint

**Highlight**: All P0 issues in red

**Columns**: Title, Status, Priority, Phase, Sprint, Related User Stories, Upstream Issue

### View 4: Current Sprint Detail
**Type**: Table
**Purpose**: Detailed view of current sprint work

**Filters**:
- `Sprint = "Sprint 2"` (update each sprint)

**Columns**:
- Title
- Status
- Assignees
- Story Points
- Priority
- Phase
- Type
- Risk Level

**Group By**: Status

**Show Totals**: Sum of Story Points by status

### View 5: Roadmap
**Type**: Roadmap (Timeline)
**Purpose**: Visual timeline of phases and sprints

**X-Axis**: Sprint or Phase
**Y-Axis**: Issue
**Color By**: Priority

**Filters**: All items with Sprint assigned

### View 6: Burndown Chart (Manual)
**Type**: Table with custom calculation

Since GitHub Projects doesn't have built-in burndown charts, create a table:

**Columns**:
- Sprint
- Total SP (manual calculation)
- Completed SP (sum of Done issues)
- Remaining SP (Total - Completed)
- Burndown Rate

**Update**: At end of each sprint

---

## Part 3: Adding Issues to Project

Now add all the issues we created to the project:

### Issues Created (2025-10-30)

1. **Issue #2**: [Sprint 2] Priority String Parser Implementation
   - **Sprint**: Sprint 2
   - **Story Points**: 8
   - **Priority**: P1 - High
   - **Phase**: Phase 1
   - **Type**: Feature
   - **Status**: In Progress

2. **Issue #3**: [Sprint 2] Session Cache Implementation & Testing
   - **Sprint**: Sprint 2
   - **Story Points**: 5
   - **Priority**: P2 - Medium
   - **Phase**: Phase 1
   - **Type**: Feature
   - **Status**: Done (implementation complete, testing deferred to Sprint 3)

3. **Issue #4**: [CRITICAL] C23 Standard Compliance
   - **Sprint**: Sprint 2
   - **Story Points**: 13
   - **Priority**: P0 - Critical
   - **Phase**: Phase 1
   - **Type**: Technical Debt
   - **Status**: Backlog
   - **Risk Level**: Critical

4. **Issue #5**: [Phase 1] TLS Backend Abstraction Refactoring
   - **Sprint**: Sprint 3
   - **Story Points**: 21
   - **Priority**: P1 - High
   - **Phase**: Phase 1
   - **Type**: Feature
   - **Status**: Backlog

5. **Issue #6**: [Phase 2] wolfSSL Wrapper Layer Implementation
   - **Sprint**: Backlog (Sprint 5-6)
   - **Story Points**: 21
   - **Priority**: P1 - High
   - **Phase**: Phase 2
   - **Type**: Feature
   - **Status**: Backlog

6. **Issue #7**: [Phase 2] TLS Connection Handling Migration
   - **Sprint**: Backlog (Sprint 6-7)
   - **Story Points**: 34
   - **Priority**: P1 - High
   - **Phase**: Phase 2
   - **Type**: Feature
   - **Status**: Backlog

7. **Issue #8**: [SECURITY] US-031: TLS Version Enforcement
   - **Sprint**: Sprint 3
   - **Story Points**: 13
   - **Priority**: P0 - Critical
   - **Phase**: Phase 1
   - **Type**: Security
   - **Status**: Backlog
   - **Upstream Issue**: `#585`
   - **Related User Stories**: `US-031`
   - **Risk Level**: Critical

8. **Issue #9**: [SECURITY] US-032: Multi-Factor Auth Broken
   - **Sprint**: Sprint 4
   - **Story Points**: 13
   - **Priority**: P0 - Critical
   - **Phase**: Phase 2
   - **Type**: Security
   - **Status**: Backlog
   - **Upstream Issue**: `#323`
   - **Related User Stories**: `US-032`
   - **Risk Level**: Critical

9. **Issue #10**: [SECURITY] US-033: Worker Process Deadlock
   - **Sprint**: Sprint 5
   - **Story Points**: 21
   - **Priority**: P0 - Critical
   - **Phase**: Phase 2
   - **Type**: Security
   - **Status**: Backlog
   - **Upstream Issue**: `#638`
   - **Related User Stories**: `US-033`
   - **Risk Level**: Critical

### How to Add Issues

1. Navigate to your project: https://github.com/users/dantte-lp/projects/3
2. Click **"+ Add item"** at the bottom of any column
3. Search for issue by number (e.g., `#2`, `#3`, etc.)
4. Click the issue to add it to the project
5. Set all custom fields according to the values above
6. Repeat for all 9 issues

**Bulk Add Method**:
1. Go to the project's **"Add items"** view
2. Filter by repository: `dantte-lp/wolfguard`
3. Select all issues #2-#10
4. Click **"Add selected items"**
5. Then set custom fields for each issue

---

## Part 4: Sprint Planning

### Sprint 2 (Current) - 2025-10-29 to 2025-11-13

**Sprint Goal**: Complete development tools validation, priority parser, and C23 compliance

**Sprint Backlog** (29 SP total):
- ✅ Issue #3: Session Cache (5 SP) - **DONE**
- 🔄 Issue #2: Priority Parser (8 SP) - **85% COMPLETE**
- ⏸️ Issue #4: C23 Compliance (13 SP) - **PENDING**
- ⏸️ Issue #8: TLS Version Enforcement (partially, 3 SP) - **PENDING**

**Sprint Capacity**: 29 SP (realistic for 2-week sprint)
**Progress**: 5/29 SP completed (17%)

### Sprint 3 (Next) - 2025-11-14 to 2025-11-27

**Sprint Goal**: Complete TLS backend abstraction and critical security issues

**Planned Backlog** (47 SP):
- Issue #5: TLS Backend Abstraction (21 SP)
- Issue #8: TLS Version Enforcement (13 SP - complete)
- Issue #2: Priority Parser testing (remaining 3 SP)
- Issue #4: C23 Compliance (10 SP - if not done in Sprint 2)

**Sprint Capacity**: 40-50 SP (adjust based on Sprint 2 velocity)

---

## Part 5: Automation Rules

Set up GitHub Actions automation:

### Rule 1: Auto-move to "In Progress" when PR opened

**Trigger**: Pull request opened
**Condition**: PR linked to issue
**Action**: Move issue to "In Progress" status

### Rule 2: Auto-move to "In Review" when PR ready for review

**Trigger**: PR marked as "Ready for review"
**Action**: Move linked issue to "In Review"

### Rule 3: Auto-move to "Done" when PR merged

**Trigger**: Pull request merged
**Condition**: PR linked to issue
**Action**: Move issue to "Done" status

### Rule 4: Add "blocked" label

**Manual trigger**: Add label "blocked" to issue
**Action**: Move issue to "Blocked" column

---

## Part 6: Scrum Ceremonies

### Daily Standup (Async)
**Frequency**: Daily (working days)
**Format**: Comment in project discussion board

**Template**:
```markdown
## Daily Update - [Date]

**Yesterday**:
- Completed X
- Made progress on Y

**Today**:
- Plan to work on Z
- Continue Y

**Blockers**:
- None / Blocked by X

**Burndown**:
- Completed: X SP
- Remaining: Y SP
```

### Sprint Planning
**Frequency**: Start of each sprint (every 2 weeks)
**Attendees**: Product Owner, Development Team
**Duration**: 2-4 hours

**Agenda**:
1. Review previous sprint outcomes
2. Define sprint goal
3. Select issues from product backlog
4. Estimate story points (if not estimated)
5. Assign tasks to team members
6. Commit to sprint backlog

### Sprint Review
**Frequency**: End of each sprint (every 2 weeks)
**Duration**: 1-2 hours

**Agenda**:
1. Demo completed work
2. Review sprint goal achievement
3. Update product backlog
4. Collect feedback

### Sprint Retrospective
**Frequency**: After sprint review
**Duration**: 1 hour

**Agenda**:
1. What went well?
2. What didn't go well?
3. What should we improve?
4. Action items for next sprint

### Backlog Refinement
**Frequency**: Mid-sprint (weekly)
**Duration**: 1 hour

**Agenda**:
1. Review upcoming items
2. Add details and acceptance criteria
3. Estimate story points
4. Prioritize issues

---

## Part 7: Metrics & Reporting

### Key Metrics to Track

1. **Velocity** (Story Points completed per sprint)
   - Sprint 0: 37 SP
   - Sprint 1: 34 SP
   - Sprint 2: Target 29 SP
   - Average: Calculate after Sprint 3

2. **Sprint Burndown** (SP remaining over sprint days)
   - Track daily in Sprint Detail view
   - Calculate: Remaining SP = Total SP - Completed SP

3. **Release Burndown** (Total SP remaining for v2.0.0)
   - Total estimated: ~400-500 SP
   - Completed: 71 SP (Sprints 0-1)
   - Remaining: ~330-430 SP
   - Projected sprints: 10-14 more sprints

4. **Cycle Time** (Days from "In Progress" to "Done")
   - Target: <5 days for small issues (<8 SP)
   - Target: <10 days for medium issues (8-21 SP)

5. **Defect Rate** (Bugs found per sprint)
   - Track bugs opened vs features completed

6. **Sprint Goal Success Rate**
   - Percentage of sprints meeting sprint goal
   - Target: >80%

---

## Part 8: Labels Setup

Create the following labels in the repository:

### Sprint Labels
- `sprint-0`, `sprint-1`, `sprint-2`, etc.

### Priority Labels (redundant with custom field, but useful)
- `priority-critical` (red)
- `priority-high` (orange)
- `priority-medium` (yellow)
- `priority-low` (gray)

### Phase Labels
- `phase-0`, `phase-1`, `phase-2`, etc.

### Type Labels
- `type-feature` (blue)
- `type-bug` (red)
- `type-security` (purple)
- `type-documentation` (green)
- `type-infrastructure` (cyan)

### Status Labels
- `blocked` (dark red)
- `wip` (yellow) - Work in progress
- `needs-review` (orange)
- `ready-to-merge` (green)

### Special Labels
- `good-first-issue` (purple) - For new contributors
- `help-wanted` (green)
- `breaking-change` (red)
- `upstream` (blue) - Related to upstream ocserv

---

## Part 9: GitHub CLI Commands (for automation)

Once OAuth scopes are configured, you can use these commands:

### Add Issue to Project
```bash
# Get project ID
PROJECT_ID=$(gh project list --owner dantte-lp --format json | jq -r '.projects[] | select(.number==3) | .id')

# Add issue to project
gh project item-add $PROJECT_ID --owner dantte-lp --url https://github.com/dantte-lp/wolfguard/issues/2

# Set field values
gh project item-edit --id ITEM_ID --project-id $PROJECT_ID --field-id FIELD_ID --text "Sprint 2"
```

### Bulk Operations
```bash
# Add all issues #2-#10 to project
for i in {2..10}; do
  gh project item-add $PROJECT_ID --owner dantte-lp --url https://github.com/dantte-lp/wolfguard/issues/$i
done
```

---

## Part 10: Quick Start Checklist

Follow this checklist to set up the project:

### Step 1: Custom Fields
- [ ] Create "Sprint" field (single select, options as above)
- [ ] Create "Story Points" field (number)
- [ ] Create "Priority" field (single select, P0-P3)
- [ ] Create "Phase" field (single select, Phase 0-6)
- [ ] Create "Type" field (single select)
- [ ] Create "Risk Level" field (single select)
- [ ] Create "Upstream Issue" field (text)
- [ ] Create "Related User Stories" field (text)

### Step 2: Views
- [ ] Create "Sprint Board" view (board, grouped by status)
- [ ] Create "Product Backlog" view (table, filtered by backlog)
- [ ] Create "Security Issues" view (table, filtered by security type)
- [ ] Create "Current Sprint Detail" view (table, current sprint)
- [ ] Create "Roadmap" view (roadmap/timeline)
- [ ] Create "Burndown Chart" view (table for manual tracking)

### Step 3: Add Issues
- [ ] Add issue #2 to project (set Sprint=Sprint 2, SP=8, Priority=P1)
- [ ] Add issue #3 to project (set Sprint=Sprint 2, SP=5, Priority=P2)
- [ ] Add issue #4 to project (set Sprint=Sprint 2, SP=13, Priority=P0)
- [ ] Add issue #5 to project (set Sprint=Sprint 3, SP=21, Priority=P1)
- [ ] Add issue #6 to project (set Sprint=Backlog, SP=21, Priority=P1)
- [ ] Add issue #7 to project (set Sprint=Backlog, SP=34, Priority=P1)
- [ ] Add issue #8 to project (set Sprint=Sprint 3, SP=13, Priority=P0)
- [ ] Add issue #9 to project (set Sprint=Sprint 4, SP=13, Priority=P0)
- [ ] Add issue #10 to project (set Sprint=Backlog, SP=21, Priority=P0)

### Step 4: Labels
- [ ] Create sprint labels (sprint-0 through sprint-15)
- [ ] Create priority labels (priority-critical, high, medium, low)
- [ ] Create phase labels (phase-0 through phase-6)
- [ ] Create type labels (feature, bug, security, docs, infrastructure)
- [ ] Create status labels (blocked, wip, needs-review)
- [ ] Create special labels (good-first-issue, breaking-change, upstream)

### Step 5: Automation
- [ ] Set up "PR opened → In Progress" automation
- [ ] Set up "PR ready → In Review" automation
- [ ] Set up "PR merged → Done" automation
- [ ] Set up "blocked label → Blocked column" automation

### Step 6: Documentation
- [ ] Add project link to README.md
- [ ] Document sprint schedule in project
- [ ] Add this guide to repository docs

---

## References

- **GitHub Projects Docs**: https://docs.github.com/en/issues/planning-and-tracking-with-projects
- **Scrum Guide**: https://scrumguides.org/
- **Story Point Estimation**: https://www.mountaingoatsoftware.com/blog/what-are-story-points
- **Project URL**: https://github.com/users/dantte-lp/projects/3
- **Repository**: https://github.com/dantte-lp/wolfguard

---

## Appendix A: Story Point Reference

### Fibonacci Scale

| Story Points | Effort | Duration | Examples |
|--------------|--------|----------|----------|
| 1 | Trivial | <2 hours | Documentation typo, config change |
| 2 | Very Small | 2-4 hours | Add logging, simple bug fix |
| 3 | Small | 4-8 hours | Unit test suite, small feature |
| 5 | Medium-Small | 1 day | API endpoint, integration test |
| 8 | Medium | 1-2 days | Complex feature, refactoring |
| 13 | Large | 2-3 days | Major component, migration task |
| 21 | Very Large | 3-5 days | Core subsystem, security feature |
| 34 | Epic | 5-10 days | Major migration, phase completion |
| 55+ | Mega-Epic | >10 days | Should be broken down |

### Estimation Guidelines

**Consider**:
- Complexity (technical difficulty)
- Uncertainty (unknowns, research needed)
- Effort (raw time to implement)
- Risk (technical risk, integration risk)

**Do NOT include**:
- Delays (waiting for review, CI)
- Meetings (standup, planning)
- Context switching

---

## Appendix B: Sprint Template

Use this template for each new sprint:

```markdown
# Sprint X: [Sprint Name]

**Duration**: [Start Date] to [End Date] (2 weeks)
**Sprint Goal**: [One sentence describing the sprint objective]

## Sprint Backlog

| Issue | Title | SP | Priority | Assignee | Status |
|-------|-------|----|---------|---------| -------|
| #X | [Title] | X | PX | @user | Todo |
| #Y | [Title] | Y | PY | @user | In Progress |

**Total Capacity**: X SP
**Committed**: Y SP

## Sprint Progress

**Completed**: X SP
**Remaining**: Y SP
**Burndown Rate**: Z SP/day

## Sprint Notes

- [Daily notes, decisions, blockers]

## Sprint Review

**Demo Date**: [Date]
**Attendees**: [List]
**Outcomes**: [What was completed]

## Sprint Retrospective

**What Went Well**:
- [Item 1]

**What Didn't Go Well**:
- [Item 1]

**Action Items**:
- [Action 1]
```

---

**Document Version**: 1.0
**Last Updated**: 2025-10-30
**Next Review**: After Sprint 2 completion (2025-11-13)
