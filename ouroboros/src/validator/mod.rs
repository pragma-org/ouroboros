/// Generic trait for validating any type of data. Designed to be used across threads so validations
/// can be done in parallel. Validators should handle all error cases internally and simply return
/// a boolean indicating if the validation was successful.
pub trait Validator: Send + Sync {
    fn validate(&self) -> bool;
}
