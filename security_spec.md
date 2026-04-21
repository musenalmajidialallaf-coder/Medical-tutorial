# Firebase Security Specification - Med Tutor

## 1. Data Invariants
- **Identity Integrity**: All documents owned by a user must have a `uid` or `userId` field matching `request.auth.uid`.
- **Relational Integrity**: Lectures must be stored under the correct user's document path `/users/{userId}/lectures/{lectureId}` where `{userId} == request.auth.uid`.
- **Immutable Fields**: `uid`, `createdAt`, and `id` must not be changed after creation.
- **Privilege Separation**: Only admins (verified by the `admins` collection) can manage `admins` and `feedbacks`.
- **Public Visibility**: Public profiles are readable by all authenticated users to support leaderboards, but only editable by the owner.

## 2. The Dirty Dozen (Test Cases)

| ID | Attack Vector | Target Path | Payload / Action | Expected Result |
|----|---------------|-------------|------------------|-----------------|
| D1 | Identity Spoofing | `/users/other_id` | Create with `uid: "my_id"` | DENY |
| D2 | Identity Spoofing | `/users/my_id/lectures/L1` | Create with `uid: "other_id"` | DENY |
| D3 | Privilege Escalation | `/users/my_id` | Update `{ subscription: "paid" }` | DENY |
| D4 | Shadow Field Injection | `/users/my_id` | Update `{ role: "admin" }` | DENY |
| D5 | Admin Spoofing | `/admins/my_email` | Create record | DENY |
| D6 | List Query Scraping | `/feedbacks` | List (all) | DENY |
| D7 | Resource Poisoning | `/users/INVALID_ID_#$` | Create document | DENY |
| D8 | Resource Poisoning | `/users/my_id` | Create with 2MB string in `displayName` | DENY |
| D9 | Terminal State Lock | `/users/my_id` | Change `uid` after creation | DENY |
| D10| PII Leak | `/users/other_id` | Get document | DENY |
| D11| Timestamp Spoofing | `/feedbacks/F1` | Create with `createdAt: 12345` (client timestamp) | DENY |
| D12| Anonymous Write | `/users/my_id` | Create without auth | DENY |

## 3. Security Implementation Plan
- Implement `isValidId` and `isValid[Entity]` helpers for all collections.
- Use `isSignedIn()` instead of `isAuthenticated()`.
- Use `request.time` for all timestamp validations.
- Use `affectedKeys().hasOnly()` for fine-grained update control.
- Implement the "Master Gate" for subcollections.
