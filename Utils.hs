module Utils where

import Debug.Trace

tracem :: Monad m => String -> m ()
tracem = flip trace (return ())

forMn_ :: Monad m => [a] -> (a -> Int -> m b) -> m ()
forMn_ = go 0
  where
    go _ []     _ = return ()
    go n (x:xs) f = f x n >> go (n+1) xs f
