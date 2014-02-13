{-# LANGUAGE LambdaCase, TupleSections #-}
{-# LANGUAGE PackageImports #-}

module ThreadManager
    ( ThreadManager     -- Hide implementation
    , ThreadStatus(..)
    , FinishedThreadStatus
    , fork
    , getStatus
    , newManager
    , waitAll
    , waitAll_
    , waitFor
    , withManager
    , withManager_
    ) where

import           Control.Exception
import           Control.Concurrent  (MVar, ThreadId, forkIO, newEmptyMVar, newMVar, modifyMVar, putMVar, takeMVar, tryTakeMVar)
import           Control.Concurrent.Suspend
import           Control.Concurrent.Timer
import           Control.Monad       (void, liftM)
import           Control.Monad.Trans
import           Data.Map            (Map)
import qualified Data.Map            as M

data ThreadStatus a = Running
                    | Finished a
                    | Threw SomeException

type FinishedThreadStatus a = Either SomeException a

-- A ThreadManager is a mutable Map from ThreadId to ThreadStatus, where the
-- ThreadStatus itself is kept in an MVar. An Empty MVar means the thread is
-- still running. Otherwise, its result is in the ThreadStatus.
newtype ThreadManager a = Mgr (MVar (ThreadMap a))
type ThreadMap a = Map ThreadId (MVar (ThreadStatus a))

-- | Create a new ThreadManager.
newManager :: MonadIO m => m (ThreadManager a)
newManager = Mgr `liftM` liftIO (newMVar M.empty)

-- | Fork a new thread, managed by the given manager.
fork :: ThreadManager a -> IO a -> IO ThreadId
fork (Mgr mgr) action =
    modifyMVar mgr $ \m -> do
        state <- newEmptyMVar
        tid <- forkIO $ try action >>= putMVar state . either Threw Finished
        return (M.insert tid state m, tid)

-- | Get the thread status of a given thread.
getStatus :: ThreadManager a -> ThreadId -> IO (Maybe (ThreadStatus a))
getStatus (Mgr mgr) tid = do
    modifyMVar mgr $ \m -> do
        case M.lookup tid m of
            Nothing      -> return (m, Nothing)
            Just mstatus -> tryTakeMVar mstatus >>= \case
                Nothing     -> return (m, Just Running)
                Just status -> return (M.delete tid m, Just status)

-- | Wait for a thread to finish, or throw an error. Returns Nothing if the
-- thread was not managed in the first place.
waitFor :: ThreadManager a -> ThreadId -> IO (Maybe (ThreadStatus a))
waitFor (Mgr mgr) tid = do
    modifyMVar mgr $ \m -> do
        case M.lookup tid m of
            Nothing      -> return (m, Nothing)
            Just mstatus -> fmap ((M.delete tid m,) . Just) (takeMVar mstatus)

-- | Wait for all managed threads. Return all of their FinishedThreadStatuses.
waitAll :: ThreadManager a -> IO [FinishedThreadStatus a]
waitAll (Mgr mgr) = fmap (map finishedThreadStatus) $ modifyMVar mgr elems >>= mapM takeMVar
  where
    elems :: ThreadMap a -> IO (ThreadMap a, [MVar (ThreadStatus a)])
    elems = return . (M.empty,) . M.elems

    finishedThreadStatus :: ThreadStatus a -> FinishedThreadStatus a
    finishedThreadStatus (Finished a) = Right a
    finishedThreadStatus (Threw e)    = Left e
    finishedThreadStatus Running      = undefined -- will never be reached

waitAll_ :: ThreadManager a -> IO ()
waitAll_ = void . waitAll

-- | Execute an action with a new ThreadManager, and wait on all the launched threads.
withManager :: (ThreadManager a -> IO ()) -> IO [FinishedThreadStatus a]
withManager f = do
    manager <- newManager
    f manager
    waitAll manager

withManager_ :: (ThreadManager a -> IO ()) -> IO ()
withManager_ = void . withManager
