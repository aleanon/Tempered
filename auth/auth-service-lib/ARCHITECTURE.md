# Auth Service Library Architecture

## Design Decision: Multiple `with_state()` Calls

You might notice that the router uses `.with_state()` after each route instead of a single `.with_state()` at the end. This is an intentional design choice based on Axum's architecture and Rust's type system.

### Why Not a Single Unified State?

**The Problem:**
Each route handler has different state requirements:
- `/signup` only needs `UserStore`
- `/login` needs `UserStore`, `TwoFaCodeStore`, and `EmailClient`
- `/logout` only needs `BannedTokenStore`
- etc.

**Attempted Solution:**
We initially tried creating a unified `AuthServiceState` struct with all stores and using wrapper functions to extract the needed stores for each route. However, this approach fails due to Axum's constraints:

```rust
// This doesn't work - generic functions can't be used directly in routes
pub async fn login_handler<U, B, T, E>(
    State(state): State<AuthServiceState<U, B, T, E>>,
    ...
) -> Result<impl IntoResponse, AuthApiError>
```

Axum requires concrete types at compile time when building routes. Generic handler functions with type parameters cannot be directly used in the router because the type parameters must be known at compile time, but they're not available until the `AuthService::new()` method is called with specific implementations.

**Why the Current Approach is Better:**

1. **Type Safety** - Each route gets exactly the state it needs, no more, no less
2. **Zero Runtime Overhead** - No wrapper functions means no extra function call overhead
3. **Explicit Dependencies** - Clear which stores each route depends on
4. **Memory Efficiency** - Routes that only need one store don't get an entire state struct

### Performance Considerations

The multiple `.with_state()` calls happen **once** at router construction time, not on every request. At runtime:
- No extra allocations
- No wrapper function calls
- Direct handler invocation
- Minimal memory footprint per route

### Alternative Approaches Considered

1. **Boxing Handlers** - Would add heap allocation and dynamic dispatch overhead
2. **Macro-based Routing** - Complex, harder to maintain, and doesn't solve the fundamental issue
3. **Runtime State Selection** - Would require `Any` downcasting, losing type safety

### Conclusion

While it may look verbose, this approach is actually the most efficient and idiomatic way to handle different state requirements per route in Axum. It's a compile-time optimization that results in the best runtime performance.

## References

- [Axum's State documentation](https://docs.rs/axum/latest/axum/extract/struct.State.html)
- [Axum issue on generic handlers](https://github.com/tokio-rs/axum/issues/1155)
