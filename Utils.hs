{-# LANGUAGE ScopedTypeVariables #-}

module Utils where

import Control.Exception
import Debug.Trace

tracem :: Monad m => String -> m ()
tracem = flip trace (return ())

forMn_ :: Monad m => [a] -> (a -> Int -> m b) -> m ()
forMn_ = go 0
  where
    go _ []     _ = return ()
    go n (x:xs) f = f x n >> go (n+1) xs f

-- | Run an action to completion. If it throws an exception, run the second
-- action to completion.
catch' :: IO a -> IO a -> IO a
catch' a b = a `catch` (\(_ :: SomeException) -> b)
